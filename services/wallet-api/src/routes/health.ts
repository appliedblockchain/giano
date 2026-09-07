import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';

export default async function healthRoutes(
  instance: FastifyInstance,
  opts: {
    db: Db;
    version: string;
    chainId: number;
    /** Absent when this deployment does not sponsor gas. */
    sponsorshipHealth?: () => Promise<'ok' | 'unavailable'>;
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
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
    { schema: { tags: ['health'], response: { 200: z.object({ version: z.string(), chainId: z.number() }) } } },
    async () => ({ version: opts.version, chainId: opts.chainId }),
  );
}
