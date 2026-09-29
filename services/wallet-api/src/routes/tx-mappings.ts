import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { createTxMappingService } from '../services/tx-mappings.js';

/**
 * What the wallet origin reads when a transaction is under review: the tenant's currently valid
 * transaction display mappings for one chain.
 *
 * Tenant by Origin *or Host*, no session (design D7). The mapping set is not user-specific and
 * holds no secrets, and the review screen must not wait on the silent session restore that runs
 * alongside it (WK-12). The Host fallback exists because this is a same-origin GET: the wallet
 * calls `/api/v1/tx-mappings` through its own nginx, and browsers send no Origin header on a
 * same-origin GET — the same reason `/.well-known/webauthn` resolves by Host. Either way, an
 * unregistered caller learns nothing: 403, as on the ceremony routes.
 */
export default async function txMappingRoutes(instance: FastifyInstance, opts: { db: Db }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();

  const requireTenantByOriginOrHost = async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.tenant) return; // resolved from Origin by the tenant plugin's onRequest hook
    const host = request.headers.host;
    const tenant = host ? await app.tenants.getByHost(host) : null;
    if (!tenant) {
      return reply.code(403).send({ error: 'unknown-tenant', message: 'neither Origin nor Host names a registered tenant wallet origin' });
    }
    request.tenant = tenant;
    request.log = request.log.child({ tenant: tenant.slug });
  };

  app.addHook('preHandler', requireTenantByOriginOrHost);
  app.addHook('preHandler', app.requireChain);

  const mappings = createTxMappingService(opts.db);

  app.get(
    '/v1/tx-mappings',
    {
      schema: {
        tags: ['wallet'],
        summary: "The tenant's transaction display mappings for one chain, as the wallet consumes them",
        description:
          'ERC-7730 descriptors, re-validated on read: a stored descriptor that no longer passes validation is ' +
          'omitted (and flagged on the admin listing) rather than served. The tenant is the Origin header when present, ' +
          'else the Host (a same-origin GET carries no Origin). Cached for a minute by the wallet.',
        querystring: z.object({ chainId: z.coerce.number().int().positive().optional() }),
        response: {
          200: z.object({
            chainId: z.number(),
            mappings: z.array(z.unknown()),
            /** Newest change to any mapping on this chain, valid or not; null when there are none. */
            updatedAt: z.string().nullable(),
          }),
        },
      },
    },
    async (request, reply) => {
      const tenant = request.tenant!;
      const chainId = request.chain!.chainId;
      const served = await mappings.listForServing(tenant.id, chainId);
      for (const contract of served.invalid) {
        request.log.warn({ txMappings: 'invalid-skipped', chainId, contract }, 'stored transaction mapping fails validation and was not served');
      }
      reply.header('cache-control', 'private, max-age=60');
      return { chainId, mappings: served.mappings, updatedAt: served.updatedAt?.toISOString() ?? null };
    },
  );
}
