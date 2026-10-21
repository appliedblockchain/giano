import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Address, Hex } from 'viem';
import type { Logger } from 'pino';
import { z } from 'zod';
import { ERROR_CODES, RpcError } from './errors.js';
import type { Estimator } from './estimator.js';
import type { Lookup } from './lookup.js';
import type { Metrics } from './metrics.js';
import type { Submitter } from './submitter.js';
import { addressSchema, estimateUserOpSchema, hash32Schema, signedUserOpSchema, toUserOp } from './userop.js';

/**
 * The JSON-RPC surface wallet-api speaks to, which is the ERC-4337 subset it used with Alto:
 * eth_sendUserOperation, eth_estimateUserOperationGas, eth_getUserOperationReceipt,
 * eth_getUserOperationByHash, eth_supportedEntryPoints and eth_chainId. Anything else is
 * method-not-found. Errors are HTTP 200 with a JSON-RPC error object; only a malformed HTTP
 * request gets an HTTP error.
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
    context.metrics.rpcRequests.inc({ method: 'unknown', outcome: String(ERROR_CODES.methodNotFound) });
    return { jsonrpc: '2.0', id, error: { code: ERROR_CODES.methodNotFound, message: `the method ${method} does not exist / is not available` } };
  }
  try {
    const result = await handler(raw);
    context.metrics.rpcRequests.inc({ method, outcome: 'ok' });
    return { jsonrpc: '2.0', id, result };
  } catch (error) {
    if (error instanceof RpcError) {
      context.metrics.rpcRequests.inc({ method, outcome: String(error.code) });
      context.log.info({ method, code: error.code, message: error.message }, 'request refused');
      return { jsonrpc: '2.0', id, error: { code: error.code, message: error.message, ...(error.data === undefined ? {} : { data: error.data }) } };
    }
    context.metrics.rpcRequests.inc({ method, outcome: String(ERROR_CODES.internal) });
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

/** Any POST path is the JSON-RPC endpoint (Alto served `/`, `/rpc` and `/:version/rpc`). */
export function createRpcServer(context: RpcContext, ready: () => boolean): Server {
  const methods = createMethods(context);
  return createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/health') {
        const ok = ready();
        return reply(response, ok ? 200 : 503, {
          status: ok ? 'ok' : 'starting',
          chainId: context.chainId,
          entryPoint: context.entryPoint,
          executors: context.submitter.executors,
          pendingUserOperations: context.submitter.pending(),
        });
      }
      if (request.method === 'GET' && request.url === '/metrics') {
        return reply(response, 200, await context.metrics.registry.metrics(), context.metrics.registry.contentType);
      }
      if (request.method !== 'POST') return reply(response, 405, { error: 'method not allowed' });

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
        return reply(response, 200, await Promise.all(body.map((item) => handleJsonRpc(context, methods, item))));
      }
      return reply(response, 200, await handleJsonRpc(context, methods, body));
    } catch (error) {
      context.log.error({ err: error }, 'http request failed');
      if (!response.headersSent) reply(response, 500, { error: 'internal error' });
    }
  });
}
