import { eq } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { useropLog } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { ChainRegistry } from '../services/chains.js';
import { rpcUserOpSchema, type UseropRelay } from '../services/userop-relay.js';

export default async function useropRoutes(
  instance: FastifyInstance,
  opts: {
    db: Db;
    registry: ChainRegistry;
    relay: UseropRelay;
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  // request.tenant is backfilled from the session by requireSession, so no tenant
  // service is needed here — the merged policy reads straight off the request.
  const { db, registry, relay } = opts;

  const relayLimit = async (request: FastifyRequest, reply: FastifyReply) => {
    const session = request.session;
    if (!session || !request.chain) return; // requireSession/requireChain already replied
    const slot = relay.takeRelaySlot({ session, tenant: request.tenant, chain: request.chain });
    if (!slot.ok) {
      return reply.code(429).send({ error: 'rate-limited', message: `tenant relay limit of ${slot.max}/minute exceeded` });
    }
  };

  app.post(
    '/v1/userops',
    {
      // requireChain BEFORE the rate limit: an unserved chain is refused without consuming
      // any of the tenant's window.
      preHandler: [app.requireSession, app.requireChain, relayLimit],
      schema: {
        tags: ['userops'],
        security: [{ session: [] }],
        body: z.object({
          userOperation: rpcUserOpSchema,
          /**
           * The chain to submit to. Required when the deployment serves several chains;
           * optional when it serves one, where it must then match (MC-53). Validated against
           * the closed configured registry before any work happens (MC-51, MC-52).
           */
          chainId: z.number().int().positive().optional(),
        }),
        response: {
          200: z.object({ userOperationHash: z.string(), duplicate: z.boolean().optional() }),
          400: z.object({ error: z.string(), message: z.string(), servedChainIds: z.array(z.number()).optional() }),
          403: z.object({ error: z.string(), message: z.string(), policy: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })) }),
          429: z.object({ error: z.string(), message: z.string() }),
          503: z.object({ error: z.string(), message: z.string() }),
        },
      },
    },
    async (request, reply) => {
      const outcome = await relay.relay(
        { session: request.session!, tenant: request.tenant, chain: request.chain!, log: request.log },
        request.body.userOperation,
      );
      switch (outcome.kind) {
        case 'rejected':
          return reply.code(403).send({ error: 'policy-rejected', message: outcome.reason, policy: outcome.policy });
        case 'conflict':
          throw new ApiError(409, 'duplicate', 'user operation was already submitted');
        case 'submitted':
          return outcome.duplicate
            ? { userOperationHash: outcome.userOperationHash, duplicate: true }
            : { userOperationHash: outcome.userOperationHash };
      }
    },
  );

  app.get(
    '/v1/userops/:hash',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['userops'],
        security: [{ session: [] }],
        params: z.object({ hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }),
        response: {
          200: z.object({
            userOperationHash: z.string(),
            chainId: z.number(),
            sender: z.string(),
            status: z.enum(['accepted', 'rejected', 'submitted', 'failed']),
            policyResults: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })),
            rejectReason: z.string().nullable(),
            createdAt: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const row = await db.query.useropLog.findFirst({ where: eq(useropLog.useropHash, request.params.hash) });
      if (!row || row.userId !== request.session!.userId || row.tenantId !== request.session!.tenantId) {
        throw new ApiError(404, 'not-found', 'user operation not found');
      }
      return {
        userOperationHash: row.useropHash,
        chainId: row.chainId,
        sender: row.sender,
        status: row.status,
        policyResults: row.policyResults as never,
        rejectReason: row.rejectReason,
        createdAt: row.createdAt.toISOString(),
      };
    },
  );

  /**
   * Public, read-only receipt lookup (on-chain public data). Deliberately tenant-free
   * and unauthenticated (D3.7): the receipt is public chain state, and thin-SDK dApps
   * await inclusion here without ever needing a bundler URL of their own (P3.4).
   */
  app.get(
    '/v1/userops/:hash/receipt',
    {
      schema: {
        tags: ['userops'],
        params: z.object({ hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }),
        response: { 200: z.object({ receipt: z.unknown().nullable() }) },
      },
    },
    async (request) => {
      // No chainId parameter: the operation hash commits to the chain, and userop_log now
      // records it (MC-59) — so the chain is resolved from the logged row and the SDK's
      // receipt polling keeps working untouched (§9.3). An op this deployment never relayed
      // falls back to the sole chain when one is configured, and is unknown otherwise.
      const row = await db.query.useropLog.findFirst({ where: eq(useropLog.useropHash, request.params.hash) });
      const chain = (row && registry.tryGet(row.chainId)) || (registry.size === 1 ? registry.sole : undefined);
      if (!chain) return { receipt: null };
      const receipt = await chain.bundler.getUserOperationReceipt(request.params.hash);
      return { receipt };
    },
  );
}
