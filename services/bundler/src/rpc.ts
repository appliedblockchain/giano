import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Address, Hex } from 'viem';
import type { Logger } from 'pino';
import { z } from 'zod';
import { ERROR_CODES, RpcError } from './errors.js';
import type { Estimator } from './estimator.js';
import type { Lookup } from './lookup.js';
import type { Metrics } from './metrics.js';
import type { ChainRegistry } from './registry.js';
import type { Submitter } from './submitter.js';
import { addressSchema, estimateUserOpSchema, hash32Schema, signedUserOpSchema, toUserOp } from './userop.js';

/**
 * The JSON-RPC surface wallet-api speaks to, which is the ERC-4337 subset it used with Alto:
 * eth_sendUserOperation, eth_estimateUserOperationGas, eth_getUserOperationReceipt,
 * eth_getUserOperationByHash, eth_supportedEntryPoints and eth_chainId. Anything else is
 * method-not-found. One endpoint per chain, `POST /<chainId>`: a bundler client is configured with
 * one URL and names no chain in its calls. Errors are HTTP 200 with a JSON-RPC error object; a
 * request for a chain this process does not serve, or cannot serve yet, gets an HTTP error.
 */

export type RpcContext = {
  chainId: number;
  entryPoint: Address;
  estimator: Estimator;
  submitter: Submitter;
  lookup: Lookup;
  metrics: Metrics;
  log: Logger;
};

const requestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  method: z.string(),
  params: z.array(z.unknown()).optional(),
});

type JsonRpcId = string | number | null;
type JsonRpcResponse =
  | { jsonrpc: '2.0'; id: JsonRpcId; result: unknown }
  | { jsonrpc: '2.0'; id: JsonRpcId; error: { code: number; message: string; data?: unknown } };

const MAX_BODY_BYTES = 2 * 1024 * 1024;

function params<T extends z.ZodTypeAny>(method: string, schema: T, value: unknown[], usage: string): z.infer<T> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RpcError(ERROR_CODES.invalidParams, `${method} expects ${usage}: ${issue.path.join('.') || 'params'} ${issue.message}`);
  }
  return parsed.data;
}

export function createMethods(context: RpcContext) {
  const { chainId, entryPoint, estimator, submitter, lookup } = context;

  const checkEntryPoint = (requested: Address) => {
    if (requested.toLowerCase() !== entryPoint.toLowerCase()) {
      throw new RpcError(ERROR_CODES.invalidParams, `EntryPoint ${requested} is not supported; this bundler serves ${entryPoint}`);
    }
  };

  const hex = (value: bigint): Hex => `0x${value.toString(16)}`;

  return {
    eth_chainId: async () => hex(BigInt(chainId)),

    eth_supportedEntryPoints: async () => [entryPoint],

    eth_estimateUserOperationGas: async (raw: unknown[]) => {
      if (raw.length > 2) {
        throw new RpcError(ERROR_CODES.invalidParams, 'eth_estimateUserOperationGas does not take state overrides here');
      }
      const [op, requested] = params(
        'eth_estimateUserOperationGas',
        z.tuple([estimateUserOpSchema, addressSchema]),
        raw,
        '[userOperation, entryPoint]',
      );
      checkEntryPoint(requested);
      const gas = await estimator.estimate(toUserOp(op));
      return {
        preVerificationGas: hex(gas.preVerificationGas),
        verificationGasLimit: hex(gas.verificationGasLimit),
        callGasLimit: hex(gas.callGasLimit),
        paymasterVerificationGasLimit: hex(gas.paymasterVerificationGasLimit),
        paymasterPostOpGasLimit: hex(gas.paymasterPostOpGasLimit),
      };
    },

    eth_sendUserOperation: async (raw: unknown[]) => {
      const [op, requested] = params('eth_sendUserOperation', z.tuple([signedUserOpSchema, addressSchema]), raw, '[userOperation, entryPoint]');
      checkEntryPoint(requested);
      return submitter.send(toUserOp(op));
    },

    eth_getUserOperationReceipt: async (raw: unknown[]) => {
      const [hash] = params('eth_getUserOperationReceipt', z.tuple([hash32Schema]), raw, '[userOperationHash]');
      return lookup.receipt(hash);
    },

    eth_getUserOperationByHash: async (raw: unknown[]) => {
      const [hash] = params('eth_getUserOperationByHash', z.tuple([hash32Schema]), raw, '[userOperationHash]');
      return lookup.byHash(hash);
    },
  } satisfies Record<string, (params: unknown[]) => Promise<unknown>>;
}

export async function handleJsonRpc(context: RpcContext, methods: ReturnType<typeof createMethods>, body: unknown): Promise<JsonRpcResponse> {
  const parsed = requestSchema.safeParse(body);
  if (!parsed.success) {
    return { jsonrpc: '2.0', id: null, error: { code: ERROR_CODES.invalidRequest, message: 'invalid JSON-RPC request' } };
  }
  const { id = null, method, params: raw = [] } = parsed.data;
  const handler = Object.hasOwn(methods, method) ? methods[method as keyof typeof methods] : undefined;
  if (!handler) {
    context.metrics.rpcRequests.inc({ chain: String(context.chainId), method: 'unknown', outcome: String(ERROR_CODES.methodNotFound) });
    return { jsonrpc: '2.0', id, error: { code: ERROR_CODES.methodNotFound, message: `the method ${method} does not exist / is not available` } };
  }
  try {
    const result = await handler(raw);
    context.metrics.rpcRequests.inc({ chain: String(context.chainId), method, outcome: 'ok' });
    return { jsonrpc: '2.0', id, result };
  } catch (error) {
    if (error instanceof RpcError) {
      context.metrics.rpcRequests.inc({ chain: String(context.chainId), method, outcome: String(error.code) });
      context.log.info({ method, code: error.code, message: error.message }, 'request refused');
      return { jsonrpc: '2.0', id, error: { code: error.code, message: error.message, ...(error.data === undefined ? {} : { data: error.data }) } };
    }
    context.metrics.rpcRequests.inc({ chain: String(context.chainId), method, outcome: String(ERROR_CODES.internal) });
    context.log.error({ method, err: error }, 'request failed');
    return { jsonrpc: '2.0', id, error: { code: ERROR_CODES.internal, message: 'internal error' } };
  }
}

async function readBody(request: IncomingMessage): Promise<string> {
  let length = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    length += (chunk as Buffer).length;
    if (length > MAX_BODY_BYTES) throw new Error('body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function reply(response: ServerResponse, status: number, body: unknown, contentType = 'application/json') {
  response.writeHead(status, { 'content-type': contentType });
  response.end(typeof body === 'string' ? body : JSON.stringify(body));
}

const CHAIN_PATH = /^\/(\d+)\/?$/;

function rpcFailure(response: ServerResponse, status: number, code: number, message: string) {
  reply(response, status, { jsonrpc: '2.0', id: null, error: { code, message } });
}

export function createRpcServer(options: { registry: ChainRegistry; metrics: Metrics; log: Logger }): Server {
  const { registry, metrics, log } = options;
  const methodsByChain = new Map<number, ReturnType<typeof createMethods>>();

  /** The chain a request is for: `/<chainId>`, or `/` when exactly one chain is served (MC-53). */
  const resolve = (response: ServerResponse, path: string): RpcContext | undefined => {
    const served = registry.servedChainIds();
    let chainId: number;
    const match = CHAIN_PATH.exec(path);
    if (match) {
      chainId = Number(match[1]);
    } else if (path === '/' && served.length === 1) {
      chainId = served[0];
    } else if (path === '/') {
      rpcFailure(response, 400, ERROR_CODES.invalidRequest, `this bundler serves chains ${served.join(', ')}: POST /<chainId>`);
      return undefined;
    } else {
      reply(response, 404, { error: 'not found' });
      return undefined;
    }
    const entry = registry.get(chainId);
    if (!entry) {
      rpcFailure(response, 404, ERROR_CODES.invalidParams, `this bundler does not serve chain ${chainId} (served: ${served.join(', ')})`);
      return undefined;
    }
    if (!entry.services) {
      rpcFailure(response, 503, ERROR_CODES.internal, `chain ${chainId} is not available yet: ${entry.waitingFor ?? 'connecting'}`);
      return undefined;
    }
    const { services } = entry;
    return { chainId, entryPoint: services.entryPoint, estimator: services.estimator, submitter: services.submitter, lookup: services.lookup, metrics, log: log.child({ chainId }) };
  };

  return createServer(async (request, response) => {
    try {
      const path = (request.url ?? '/').split('?')[0];
      if (request.method === 'GET' && path === '/health') {
        // Healthy while ANY chain serves: one chain's outage must not get the process — and with it
        // every other chain — restarted by the orchestrator.
        const chains = registry.all().map((entry) => ({
          chainId: entry.config.chainId,
          name: entry.config.name,
          status: entry.status,
          entryPoint: entry.config.entryPoint,
          ...(entry.waitingFor ? { waitingFor: entry.waitingFor } : {}),
          ...(entry.services ? { chainType: entry.services.chainType, pendingUserOperations: entry.services.submitter.pending() } : {}),
        }));
        const ready = chains.some((chain) => chain.status === 'ready');
        const executors = registry.all().find((entry) => entry.services)?.services?.submitter.executors ?? [];
        return reply(response, ready ? 200 : 503, { status: ready ? 'ok' : 'starting', executors, chains });
      }
      if (request.method === 'GET' && path === '/metrics') {
        return reply(response, 200, await metrics.registry.metrics(), metrics.registry.contentType);
      }
      if (request.method !== 'POST') return reply(response, 405, { error: 'method not allowed' });

      const context = resolve(response, path);
      if (!context) return;
      let methods = methodsByChain.get(context.chainId);
      if (!methods) {
        methods = createMethods(context);
        methodsByChain.set(context.chainId, methods);
      }

      let body: unknown;
      try {
        body = JSON.parse(await readBody(request));
      } catch {
        return reply(response, 200, { jsonrpc: '2.0', id: null, error: { code: ERROR_CODES.parseError, message: 'parse error' } });
      }
      if (Array.isArray(body)) {
        if (body.length === 0) {
          return reply(response, 200, { jsonrpc: '2.0', id: null, error: { code: ERROR_CODES.invalidRequest, message: 'empty batch' } });
        }
        const batch = methods;
        return reply(response, 200, await Promise.all(body.map((item) => handleJsonRpc(context, batch, item))));
      }
      return reply(response, 200, await handleJsonRpc(context, methods, body));
    } catch (error) {
      log.error({ err: error }, 'http request failed');
      if (!response.headersSent) reply(response, 500, { error: 'internal error' });
    }
  });
}
