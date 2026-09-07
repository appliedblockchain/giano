import type { FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type { ChainRegistry, ChainServices } from '../services/chains.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** The chain this request acts on — resolved and validated, never body-trusted (set by requireChain). */
    chain: ChainServices | null;
  }
  interface FastifyInstance {
    requireChain: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

/** Reads the chain a request NAMES (body, ERC-7677 params[2], or query) — a request, never an instruction. */
function extractChainId(request: FastifyRequest): number | undefined {
  const body = request.body as { chainId?: unknown; params?: unknown[] } | undefined;
  if (typeof body?.chainId === 'number') return body.chainId;
  // ERC-7677 puts the chain at params[2], as a hex quantity.
  if (Array.isArray(body?.params) && typeof body.params[2] === 'string' && /^0x[0-9a-fA-F]+$/.test(body.params[2])) {
    return Number(BigInt(body.params[2]));
  }
  const query = request.query as { chainId?: string } | undefined;
  if (query?.chainId !== undefined && /^\d+$/.test(query.chainId)) return Number(query.chainId);
  return undefined;
}

/**
 * Per-request chain resolution (MC-51, §9.3), mirroring plugins/tenant.ts: every request
 * that acts on a chain identifies it explicitly, and the backend resolves it against the
 * closed configured registry before performing any work.
 *
 * Omission is a single-chain affordance only (MC-53): with exactly one chain configured the
 * request applies to it; with several, omission is refused as ambiguous — never guessed. A
 * mistyped or absent field must not silently reach some arbitrary chain.
 *
 * `400 unsupported-chain` (permanent) and `503 chain-unavailable` (retryable) deliberately
 * mirror the transport's 4902/4901 split (MC-52, MC-55).
 */
export default fp(
  async (app, opts: { registry: ChainRegistry }) => {
    const { registry } = opts;
    app.decorateRequest('chain', null);

    app.decorate('requireChain', async (request: FastifyRequest, reply: FastifyReply) => {
      const named = extractChainId(request);
      if (named === undefined) {
        if (registry.size === 1) {
          request.chain = registry.sole;
          return;
        }
        return reply.code(400).send({
          error: 'chain-required',
          message: 'chainId is required: this deployment serves several chains',
          servedChainIds: registry.servedChainIds(),
        });
      }
      const chain = registry.tryGet(named);
      if (!chain) {
        return reply.code(400).send({
          error: 'unsupported-chain',
          message: `this deployment does not serve chain ${named}`,
          servedChainIds: registry.servedChainIds(),
        });
      }
      if (chain.status !== 'ready') {
        return reply.code(503).send({
          error: 'chain-unavailable',
          message: `chain ${named} is temporarily unavailable`,
        });
      }
      request.chain = chain;
    });
  },
  { name: 'chain' },
);
