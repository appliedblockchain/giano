import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { Address, Hex } from 'viem';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import { BundlerRpcError } from '../services/bundler.js';
import type { ChainServices } from '../services/chains.js';
import { rpcUserOpSchema, type UseropRelay } from '../services/userop-relay.js';

/**
 * The JSON-RPC bundler facade: what a wallet origin points its bundler client at.
 *
 * A wallet needs a bundler for more than the signed submission — viem's `prepareUserOperation`
 * estimates gas through it and `waitForUserOperationReceipt` polls it — so a wallet with no
 * bundler URL cannot transact at all, and a wallet origin that proxies `/bundler` straight to
 * the bundler is a public, unauthenticated relay that bypasses every policy check here and
 * drains the executor (R3/R11 in specs/INFRASTRUCTURE.md). This endpoint is the third option:
 * the same JSON-RPC surface, spoken by wallet-api, behind the session, with
 * `eth_sendUserOperation` going through the identical pipeline as `POST /v1/userops`. The
 * bundler itself stays private to this process.
 *
 * Chain-bound, so the chain is in the path: `/v1/bundler/:chainId`. `/v1/bundler` without
 * one is the single-chain affordance (MC-53) and nothing else.
 */

const hexData = z.string().regex(/^0x[0-9a-fA-F]*$/) as z.ZodType<Hex>;
const hexQuantity = z.string().regex(/^0x[0-9a-fA-F]+$/) as z.ZodType<Hex>;
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/) as z.ZodType<Address>;
const hash32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/) as z.ZodType<Hex>;

/**
 * The operation as it looks DURING estimation: gas fields are what is being asked for, and
 * the paymaster fields carry a stub. Unknown keys are dropped rather than forwarded.
 */
const estimateOpSchema = z
  .object({
    sender: address,
    nonce: hexQuantity,
    callData: hexData,
    callGasLimit: hexQuantity.optional(),
    verificationGasLimit: hexQuantity.optional(),
    preVerificationGas: hexQuantity.optional(),
    maxFeePerGas: hexQuantity.optional(),
    maxPriorityFeePerGas: hexQuantity.optional(),
    factory: address.optional(),
    factoryData: hexData.optional(),
    paymaster: address.optional(),
    paymasterVerificationGasLimit: hexQuantity.optional(),
    paymasterPostOpGasLimit: hexQuantity.optional(),
    paymasterData: hexData.optional(),
    signature: hexData.optional(),
  })
  .strip();

const jsonRpcId = z.union([z.string(), z.number(), z.null()]);

const jsonRpcRequestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: jsonRpcId,
  method: z.string(),
  params: z.array(z.unknown()).optional(),
});

/**
 * Stable codes a client can key behaviour off. `-32601`/`-32602` are JSON-RPC's own;
 * `-32010` is the same meaning it has on `/v1/paymaster`; the `-3202x` block is this
 * endpoint's. A bundler's own error passes through with the bundler's code.
 */
export const RELAY_ERROR_CODES = {
  'method-not-found': -32601,
  'invalid-params': -32602,
  'internal': -32603,
  'chain-or-entrypoint-mismatch': -32010,
  'policy-rejected': -32020,
  'rate-limited': -32021,
  'duplicate': -32022,
  'bundler-unavailable': -32023,
} as const;

type RelayErrorReason = keyof typeof RELAY_ERROR_CODES;

/** Answered locally: the wallet never needs the bundler for what this process already knows. */
const LOCAL_METHODS = new Set(['eth_chainId', 'eth_supportedEntryPoints']);

/** Forwarded after the session and rate limit, with no per-operation policy — they spend nothing. */
const READ_METHODS = new Set(['eth_getUserOperationReceipt', 'eth_getUserOperationByHash']);

type JsonRpcResponse = {
  jsonrpc: '2.0';
  id: z.infer<typeof jsonRpcId>;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

export default async function bundlerRelayRoutes(
  instance: FastifyInstance,
  opts: { config: AppConfig; relay: UseropRelay },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { config, relay } = opts;

  /**
   * Its own per-tenant window for everything that is not a submission: estimation runs once or
   * twice per transaction and receipt polling many times, so sharing the submission budget would
   * silently shrink it. Submissions take a slot from the relay's window, shared with the REST
   * endpoint — one budget however an operation arrives.
   */
  const readWindows = new Map<string, { windowStart: number; count: number }>();
  const takeReadSlot = (tenantId: string): boolean => {
    const now = Date.now();
    const window = readWindows.get(tenantId);
    if (!window || now - window.windowStart >= 60_000) {
      readWindows.set(tenantId, { windowStart: now, count: 1 });
      return true;
    }
    window.count += 1;
    return window.count <= config.BUNDLER_RELAY_RATE_LIMIT_PER_MINUTE;
  };

  // Shared by both routes below, so typed against the plain request: the body has already
  // passed `jsonRpcRequestSchema` by the time it gets here.
  const handle = async (request: FastifyRequest): Promise<JsonRpcResponse> => {
    const session = request.session!;
    const chain = request.chain!;
    const { id, method, params = [] } = request.body as z.infer<typeof jsonRpcRequestSchema>;
    const tenantSlug = request.tenant?.slug ?? 'unknown';
    const chainLabel = String(chain.chainId);

    const ok = (result: unknown, outcome = 'ok'): JsonRpcResponse => {
      app.metrics.bundlerRelay.inc({ method, outcome, tenant: tenantSlug, chain: chainLabel });
      return { jsonrpc: '2.0', id, result };
    };
    const fail = (reason: RelayErrorReason, message: string, data?: unknown): JsonRpcResponse => {
      app.metrics.bundlerRelay.inc({ method, outcome: reason, tenant: tenantSlug, chain: chainLabel });
      return { jsonrpc: '2.0', id, error: { code: RELAY_ERROR_CODES[reason], message, ...(data === undefined ? {} : { data }) } };
    };
    /** The bundler's own refusal, with the bundler's code — viem maps these to its typed errors. */
    const bundlerFailure = (error: unknown): JsonRpcResponse => {
      if (error instanceof BundlerRpcError) {
        app.metrics.bundlerRelay.inc({ method, outcome: 'bundler-error', tenant: tenantSlug, chain: chainLabel });
        return { jsonrpc: '2.0', id, error: { code: error.code, message: error.message } };
      }
      request.log.error({ err: error, method, chainId: chain.chainId }, 'bundler relay: upstream failure');
      return fail('bundler-unavailable', 'the bundler could not be reached');
    };

    if (LOCAL_METHODS.has(method)) {
      if (method === 'eth_chainId') return ok(`0x${chain.chainId.toString(16)}`);
      return ok([chain.entryPoint]);
    }

    if (READ_METHODS.has(method)) {
      if (!takeReadSlot(session.tenantId)) {
        return fail('rate-limited', `tenant bundler relay limit of ${config.BUNDLER_RELAY_RATE_LIMIT_PER_MINUTE}/minute exceeded`);
      }
      const parsed = z.tuple([hash32]).safeParse(params);
      if (!parsed.success) return fail('invalid-params', `${method} expects [userOperationHash]`);
      try {
        const result =
          method === 'eth_getUserOperationReceipt'
            ? await chain.bundler.getUserOperationReceipt(parsed.data[0])
            : await chain.bundler.getUserOperationByHash(parsed.data[0]);
        return ok(result);
      } catch (error) {
        return bundlerFailure(error);
      }
    }

    if (method === 'eth_estimateUserOperationGas') {
      if (!takeReadSlot(session.tenantId)) {
        return fail('rate-limited', `tenant bundler relay limit of ${config.BUNDLER_RELAY_RATE_LIMIT_PER_MINUTE}/minute exceeded`);
      }
      // Exactly two parameters: a state override (a legal third) would let the caller estimate
      // against a chain state of their choosing, and nothing here needs it.
      const parsed = z.tuple([estimateOpSchema, address]).safeParse(params);
      if (!parsed.success) return fail('invalid-params', 'eth_estimateUserOperationGas expects [userOperation, entryPoint]');
      const [op, entryPoint] = parsed.data;
      const mismatch = entryPointMismatch(chain, entryPoint);
      if (mismatch) return fail('chain-or-entrypoint-mismatch', mismatch);
      // Sender binding, as for a submission: estimation is a simulation the bundler pays for, and
      // it is only ever offered for the session's own wallet.
      if (op.sender.toLowerCase() !== session.walletAddress.toLowerCase()) {
        return fail('policy-rejected', `sender ${op.sender} does not match session wallet ${session.walletAddress}`, {
          reason: 'sender-binding',
        });
      }
      try {
        return ok(await chain.bundler.estimateUserOperationGas(op as unknown as Record<string, unknown>));
      } catch (error) {
        return bundlerFailure(error);
      }
    }

    if (method === 'eth_sendUserOperation') {
      const parsed = z.tuple([rpcUserOpSchema, address]).safeParse(params);
      if (!parsed.success) return fail('invalid-params', 'eth_sendUserOperation expects [userOperation, entryPoint]');
      const [op, entryPoint] = parsed.data;
      const mismatch = entryPointMismatch(chain, entryPoint);
      if (mismatch) return fail('chain-or-entrypoint-mismatch', mismatch);

      const caller = { session, tenant: request.tenant, chain, log: request.log };
      const slot = relay.takeRelaySlot(caller);
      if (!slot.ok) return fail('rate-limited', `tenant relay limit of ${slot.max}/minute exceeded`);

      let outcome;
      try {
        outcome = await relay.relay(caller, op);
      } catch (error) {
        return bundlerFailure(error);
      }
      switch (outcome.kind) {
        case 'rejected':
          return fail('policy-rejected', outcome.reason, { reason: 'policy-rejected', policy: outcome.policy });
        case 'conflict':
          return fail('duplicate', 'user operation was already submitted');
        case 'submitted':
          return ok(outcome.userOperationHash, outcome.duplicate ? 'duplicate' : 'submitted');
      }
    }

    return fail('method-not-found', `${method} is not relayed — this endpoint speaks the ERC-4337 methods a wallet needs and nothing else`);
  };

  const schema = {
    tags: ['bundler'],
    summary: 'ERC-4337 bundler relay (JSON-RPC)',
    description:
      'The bundler surface a wallet origin points its bundler client at, so the bundler itself never has to be reachable ' +
      'from a browser. eth_sendUserOperation goes through the same policy, audit and idempotency pipeline as POST /v1/userops; ' +
      'eth_estimateUserOperationGas is bound to the session wallet; eth_getUserOperationReceipt and eth_getUserOperationByHash are ' +
      'forwarded; eth_chainId and eth_supportedEntryPoints are answered from configuration. Refusals carry a stable code in `error.code`.',
    security: [{ session: [] }],
    body: jsonRpcRequestSchema,
    response: {
      200: z.object({
        jsonrpc: z.literal('2.0'),
        id: jsonRpcId,
        result: z.unknown().optional(),
        error: z.object({ code: z.number(), message: z.string(), data: z.unknown().optional() }).optional(),
      }),
      400: z.object({ error: z.string(), message: z.string(), servedChainIds: z.array(z.number()).optional() }),
      401: z.object({ error: z.string(), message: z.string() }),
      503: z.object({ error: z.string(), message: z.string() }),
    },
  };

  // The chain travels in the path: a bundler client is configured with one URL and carries no
  // chain id in its calls, so `/v1/bundler/<chainId>` is how one wallet serving several chains
  // gets one relay per chain (MC-43, MC-58).
  app.post('/v1/bundler/:chainId', {
    preHandler: [app.requireSession, app.requireChain],
    schema: { ...schema, params: z.object({ chainId: z.coerce.number().int().positive() }) },
  }, handle);

  // Single-chain affordance only (MC-53): with several chains served this is refused as ambiguous.
  app.post('/v1/bundler', { preHandler: [app.requireSession, app.requireChain], schema }, handle);
}

function entryPointMismatch(chain: ChainServices, entryPoint: Address): string | undefined {
  if (entryPoint.toLowerCase() === chain.entryPoint.toLowerCase()) return undefined;
  return `this relay serves EntryPoint ${chain.entryPoint} on chain ${chain.chainId}`;
}
