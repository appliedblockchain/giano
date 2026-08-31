import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import type { ChainRegistry } from '../services/chains.js';

export default async function healthRoutes(
  instance: FastifyInstance,
  opts: {
    db: Db;
    version: string;
    registry: ChainRegistry;
    /** Absent when this deployment does not sponsor gas. */
    sponsorshipHealth?: () => Promise<'ok' | 'unavailable'>;
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { registry } = opts;

  app.get(
    '/healthz',
    { schema: { tags: ['health'], response: { 200: z.object({ status: z.literal('ok') }) } } },
    async () => ({ status: 'ok' as const }),
  );

  app.get(
    '/readyz',
    {
      schema: {
        tags: ['health'],
        response: {
          200: z.object({ status: z.literal('ready'), sponsorship: z.enum(['ok', 'disabled']).optional() }),
          503: z.object({ status: z.literal('unavailable'), message: z.string() }),
        },
      },
    },
    async (request, reply) => {
      try {
        await opts.db.execute(sql`SELECT 1`);
      } catch (error) {
        return reply.code(503).send({ status: 'unavailable' as const, message: (error as Error).message });
      }

      // Per-chain degradation (MC-54): ONE unreachable chain must not take the deployment
      // out of rotation while the others work — readiness requires AT LEAST ONE chain ready;
      // per-chain detail lives in /v1/version and in metrics.
      if (!registry.all.some((chain) => chain.status === 'ready')) {
        return reply.code(503).send({ status: 'unavailable' as const, message: 'no configured chain is currently available' });
      }

      // A deployment whose signer is down cannot sponsor, and sponsored tenants cannot transact
      // at all without it — so it must not report itself ready. This is the difference between an
      // outage and a misconfiguration being visible in the right place.
      if (opts.sponsorshipHealth) {
        const health = await opts.sponsorshipHealth();
        if (health !== 'ok') {
          return reply.code(503).send({ status: 'unavailable' as const, message: 'the sponsorship signer is unavailable' });
        }
        return { status: 'ready' as const, sponsorship: 'ok' as const };
      }

      return { status: 'ready' as const, sponsorship: 'disabled' as const };
    },
  );

  app.get(
    '/v1/version',
    {
      schema: {
        tags: ['health'],
        response: {
          200: z.object({
            version: z.string(),
            /** The sole chain when exactly one is served; null otherwise. Kept for existing readers. */
            chainId: z.number().nullable(),
            /** Every chain this deployment serves, and the health of each (MC-56). */
            chains: z.array(z.object({ chainId: z.number(), name: z.string(), status: z.enum(['ready', 'unavailable']) })),
          }),
        },
      },
    },
    async () => ({
      version: opts.version,
      chainId: registry.size === 1 ? registry.sole.chainId : null,
      chains: registry.all.map((chain) => ({ chainId: chain.chainId, name: chain.descriptor.name, status: chain.status })),
    }),
  );
}
