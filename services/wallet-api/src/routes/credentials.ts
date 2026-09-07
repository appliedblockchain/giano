import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { credentials } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { SessionService } from '../services/sessions.js';

/**
 * Identity ALWAYS comes from the session — no endpoint accepts a userId in the URL
 * or body (this is the fix for the demo's unauthenticated storage API).
 */
export default async function credentialRoutes(
  instance: FastifyInstance, opts: { db: Db; sessions: SessionService }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { db, sessions } = opts;

  app.addHook('preHandler', app.requireSession);

  app.get(
    '/v1/me',
    {
      schema: {
        tags: ['me'],
        security: [{ session: [] }],
        response: {
          200: z.object({
            externalUserId: z.string(),
            walletAddress: z.string(),
            credentialId: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const session = request.session!;
      const credential = await db.query.credentials.findFirst({ where: eq(credentials.id, session.credentialId) });
      return {
        externalUserId: session.externalUserId,
        walletAddress: session.walletAddress,
        credentialId: credential!.credentialId,
      };
    },
  );

  app.get(
    '/v1/me/credentials',
    {
      schema: {
        tags: ['me'],
        security: [{ session: [] }],
        response: {
          200: z.object({
            credentials: z.array(
              z.object({
                credentialId: z.string(),
                walletAddress: z.string(),
                transports: z.array(z.string()).nullable(),
                createdAt: z.string(),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const rows = await db
        .select({
          credentialId: credentials.credentialId,
          walletAddress: credentials.walletAddress,
          transports: credentials.transports,
          createdAt: credentials.createdAt,
        })
        .from(credentials)
        .where(eq(credentials.userId, request.session!.userId));
      return {
        credentials: rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() })),
      };
    },
  );

  app.get(
    '/v1/me/credentials/:credentialId/public-key',
    {
      schema: {
        tags: ['me'],
        security: [{ session: [] }],
        params: z.object({ credentialId: z.string() }),
        response: { 200: z.object({ x: z.string(), y: z.string() }) },
      },
    },
    async (request) => {
      const row = await db.query.credentials.findFirst({
        where: and(eq(credentials.userId, request.session!.userId), eq(credentials.credentialId, request.params.credentialId)),
      });
      if (!row) {
        throw new ApiError(404, 'not-found', 'credential not found for this user');
      }
      return { x: row.publicKeyX, y: row.publicKeyY };
    },
  );

  app.post(
    '/v1/sessions/logout',
    { schema: { tags: ['me'], security: [{ session: [] }], response: { 200: z.object({ ok: z.literal(true) }) } } },
    async (request) => {
      await sessions.revoke(request.session!.sessionId);
      return { ok: true as const };
    },
  );
}
