import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';

export default async function healthRoutes(
  instance: FastifyInstance, opts: { db: Db; version: string; chainId: number }) {
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
          200: z.object({ status: z.literal('ready') }),
          503: z.object({ status: z.literal('unavailable'), message: z.string() }),
        },
      },
    },
    async (request, reply) => {
      try {
        await opts.db.execute(sql`SELECT 1`);
        return { status: 'ready' as const };
      } catch (error) {
        return reply.code(503).send({ status: 'unavailable' as const, message: (error as Error).message });
      }
    },
  );

  app.get(
    '/v1/version',
    { schema: { tags: ['health'], response: { 200: z.object({ version: z.string(), chainId: z.number() }) } } },
    async () => ({ version: opts.version, chainId: opts.chainId }),
  );
}
