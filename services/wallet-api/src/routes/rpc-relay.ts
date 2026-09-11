import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import { NodeRpcError } from '../services/node-rpc.js';

/**
 * The node read relay: what a wallet origin points its chain RPC client at.
 *
 * Reads are public chain state, so this is tenant-bound (by Origin) rather than session-bound —
 * the wallet reads before anyone has signed in (address derivation, fee estimation, the silent
 * restore). What it adds over dialling a node directly: the RPC URL — and any API key in it —
 * lives only in this process, and a wallet origin needs no chain configuration of its own.
 * Read-only by construction: the allowlist is the whole contract.
 *
 * Chain in the path, as for the bundler relay: `/v1/rpc/:chainId`; `/v1/rpc` is the
 * single-chain affordance (MC-53).
 */

/** What viem's public client and the wallet's own reads actually call. Nothing that spends or mutates. */
const READ_METHODS = new Set([
  'eth_call',
  'eth_getCode',
  'eth_getBalance',
  'eth_getStorageAt',
  'eth_getTransactionCount',
  'eth_estimateGas',
  'eth_gasPrice',
  'eth_maxPriorityFeePerGas',
  'eth_feeHistory',
  'eth_blockNumber',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getTransactionByHash',
  'eth_getTransactionReceipt',
  'eth_getLogs',
  'net_version',
]);

const jsonRpcId = z.union([z.string(), z.number(), z.null()]);

const jsonRpcRequestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: jsonRpcId,
  method: z.string(),
  params: z.array(z.unknown()).optional(),
});

/** `-32601`/`-32603` are JSON-RPC's own; `-32021`/`-32023` mean what they mean on `/v1/bundler`. */
const CODES = { 'method-not-found': -32601, internal: -32603, 'rate-limited': -32021, 'node-unavailable': -32023 } as const;

type JsonRpcResponse = {
  jsonrpc: '2.0';
  id: z.infer<typeof jsonRpcId>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

export default async function rpcRelayRoutes(instance: FastifyInstance, opts: { config: AppConfig }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { config } = opts;

  const windows = new Map<string, { windowStart: number; count: number }>();
  const takeSlot = (tenantId: string): boolean => {
    const now = Date.now();
    const window = windows.get(tenantId);
    if (!window || now - window.windowStart >= 60_000) {
      windows.set(tenantId, { windowStart: now, count: 1 });
      return true;
    }
    window.count += 1;
    return window.count <= config.RPC_RELAY_RATE_LIMIT_PER_MINUTE;
  };

  const handle = async (request: FastifyRequest): Promise<JsonRpcResponse> => {
    const tenant = request.tenant!;
    const chain = request.chain!;
    const { id, method, params = [] } = request.body as z.infer<typeof jsonRpcRequestSchema>;
    const labels = { method, tenant: tenant.slug, chain: String(chain.chainId) };

    const ok = (result: unknown): JsonRpcResponse => {
      app.metrics.rpcRelay.inc({ ...labels, outcome: 'ok' });
      return { jsonrpc: '2.0', id, result };
    };
    const fail = (reason: keyof typeof CODES, message: string): JsonRpcResponse => {
      app.metrics.rpcRelay.inc({ ...labels, outcome: reason });
      return { jsonrpc: '2.0', id, error: { code: CODES[reason], message } };
    };

    if (method === 'eth_chainId') return ok(`0x${chain.chainId.toString(16)}`);

    if (!READ_METHODS.has(method)) {
      return fail('method-not-found', `${method} is not relayed — this endpoint forwards read-only chain methods and nothing else`);
    }
    if (!takeSlot(tenant.id)) {
      return fail('rate-limited', `tenant RPC relay limit of ${config.RPC_RELAY_RATE_LIMIT_PER_MINUTE}/minute exceeded`);
    }
    try {
      return ok(await chain.nodeRpc.call(method, params));
    } catch (error) {
      if (error instanceof NodeRpcError) {
        // The node's own answer, code and all — a revert reason must reach the wallet intact.
        app.metrics.rpcRelay.inc({ ...labels, outcome: 'node-error' });
        return { jsonrpc: '2.0', id, error: { code: error.code, message: error.message, ...(error.data === undefined ? {} : { data: error.data }) } };
      }
      request.log.error({ err: error, method, chainId: chain.chainId }, 'rpc relay: node unreachable');
      return fail('node-unavailable', 'the chain RPC could not be reached');
    }
  };

  const schema = {
    tags: ['rpc'],
    summary: 'Chain RPC read relay (JSON-RPC)',
    description:
      'Forwards read-only JSON-RPC methods to the chain node wallet-api is configured with, so a wallet origin needs no RPC ' +
      'URL of its own and a keyed provider URL never reaches a browser. Tenant-bound by Origin, rate-limited per tenant; ' +
      'eth_chainId is answered from configuration; anything outside the read allowlist is refused with -32601.',
    body: jsonRpcRequestSchema,
    response: {
      200: z.object({
        jsonrpc: z.literal('2.0'),
        id: jsonRpcId,
        result: z.unknown().optional(),
        error: z.object({ code: z.number(), message: z.string(), data: z.unknown().optional() }).optional(),
      }),
      400: z.object({ error: z.string(), message: z.string(), servedChainIds: z.array(z.number()).optional() }),
      403: z.object({ error: z.string(), message: z.string() }),
      503: z.object({ error: z.string(), message: z.string() }),
    },
  };

  app.post('/v1/rpc/:chainId', {
    preHandler: [app.requireTenant, app.requireChain],
    schema: { ...schema, params: z.object({ chainId: z.coerce.number().int().positive() }) },
  }, handle);

  app.post('/v1/rpc', { preHandler: [app.requireTenant, app.requireChain], schema }, handle);
}
