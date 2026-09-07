import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { rorOrigins } from '../db/schema.js';

const originSchema = z
  .string()
  .url()
  .refine((value) => {
    const url = new URL(value);
    return url.origin === value;
  }, 'must be a bare origin (scheme://host[:port], no path)');

export default async function adminRoutes(
  instance: FastifyInstance, opts: { db: Db }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  app.addHook('preHandler', app.requireAdmin);

  app.get(
    '/v1/admin/ror-origins',
    { schema: { tags: ['admin'], security: [{ adminKey: [] }], response: { 200: z.object({ origins: z.array(z.object({ id: z.string(), origin: z.string() })) }) } } },
    async () => {
      const rows = await opts.db.select({ id: rorOrigins.id, origin: rorOrigins.origin }).from(rorOrigins);
      return { origins: rows };
    },
  );

  app.post(
    '/v1/admin/ror-origins',
    {
      schema: {
        tags: ['admin'],
        security: [{ adminKey: [] }],
        body: z.object({ origin: originSchema }),
        response: { 201: z.object({ id: z.string(), origin: z.string() }) },
      },
    },
    async (request, reply) => {
      const [row] = await opts.db
        .insert(rorOrigins)
        .values({ origin: request.body.origin })
        .onConflictDoUpdate({ target: rorOrigins.origin, set: { origin: request.body.origin } })
        .returning({ id: rorOrigins.id, origin: rorOrigins.origin });
      return reply.code(201).send(row);
    },
  );

  app.delete(
    '/v1/admin/ror-origins/:id',
    {
      schema: {
        tags: ['admin'],
        security: [{ adminKey: [] }],
        params: z.object({ id: z.string().uuid() }),
        response: { 204: z.null(), 404: z.object({ error: z.string(), message: z.string() }) },
      },
    },
    async (request, reply) => {
      const deleted = await opts.db.delete(rorOrigins).where(eq(rorOrigins.id, request.params.id)).returning({ id: rorOrigins.id });
      if (deleted.length === 0) {
        return reply.code(404).send({ error: 'not-found', message: 'origin not found' });
      }
      return reply.code(204).send(null);
    },
  );
}
