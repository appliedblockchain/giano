import { and, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { credentials, walletManagementLog } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { ChainRegistry } from '../services/chains.js';
import { isOwnerPublicKeyOnChain } from '../services/owner-check.js';
import type { SessionService } from '../services/sessions.js';

/**
 * Identity ALWAYS comes from the session — no endpoint accepts a userId in the URL
 * or body (this is the fix for the demo's unauthenticated storage API).
 */
export default async function credentialRoutes(
  instance: FastifyInstance,
  opts: { db: Db; sessions: SessionService; registry: ChainRegistry },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { db, sessions, registry } = opts;

  app.addHook('preHandler', app.requireSession);

  const credentialSchema = z.object({
    credentialId: z.string(),
    walletAddress: z.string(),
    /** User-set label (WM-07); null until named. Never an input to any decision (WM-11). */
    name: z.string().nullable(),
    /** The registry row joins on-chain owners by these bytes (WM-02). */
    publicKeyX: z.string(),
    publicKeyY: z.string(),
    transports: z.array(z.string()).nullable(),
    createdAt: z.string(),
    /** Set once the key was verified removed on-chain — shown as "no longer an owner" (WM-04). */
    removedAt: z.string().nullable(),
  });

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
          200: z.object({ credentials: z.array(credentialSchema) }),
        },
      },
    },
    async (request) => {
      const rows = await db
        .select({
          credentialId: credentials.credentialId,
          walletAddress: credentials.walletAddress,
          name: credentials.name,
          publicKeyX: credentials.publicKeyX,
          publicKeyY: credentials.publicKeyY,
          transports: credentials.transports,
          createdAt: credentials.createdAt,
          removedAt: credentials.removedAt,
        })
        .from(credentials)
        .where(eq(credentials.userId, request.session!.userId));
      return {
        credentials: rows.map((row) => ({
          ...row,
          createdAt: row.createdAt.toISOString(),
          removedAt: row.removedAt ? row.removedAt.toISOString() : null,
        })),
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

  /** Rename a credential (WM-07). A name is a local label, never authority (D7, WM-11). */
  app.patch(
    '/v1/me/credentials/:credentialId',
    {
      schema: {
        tags: ['me'],
        security: [{ session: [] }],
        params: z.object({ credentialId: z.string() }),
        body: z.object({ name: z.string().max(256).nullable() }),
        response: { 200: z.object({ ok: z.literal(true), name: z.string().nullable() }) },
      },
    },
    async (request) => {
      const updated = await db
        .update(credentials)
        .set({ name: request.body.name })
        .where(and(eq(credentials.userId, request.session!.userId), eq(credentials.credentialId, request.params.credentialId)))
        .returning({ name: credentials.name });
      if (updated.length === 0) {
        throw new ApiError(404, 'not-found', 'credential not found for this user');
      }
      return { ok: true as const, name: updated[0].name };
    },
  );

  /**
   * Marks a credential as no longer an owner, AFTER the chain says so (WM-31). The caller
   * is not taken at its word: on every served chain where the account has code, the key
   * must no longer be in the owner set — otherwise the registry would refuse sessions to a
   * credential that can still sign, which chain-governs (WM-36) forbids in spirit. On
   * success every session held by the credential is revoked; if that includes the calling
   * session, the response says so and the caller returns the user to a signed-out state
   * (WM-30).
   */
  app.post(
    '/v1/me/credentials/:credentialId/removed',
    {
      schema: {
        tags: ['me'],
        security: [{ session: [] }],
        params: z.object({ credentialId: z.string() }),
        response: {
          200: z.object({ ok: z.literal(true), removedCurrentSession: z.boolean() }),
          404: z.object({ error: z.string(), message: z.string() }),
          409: z.object({ error: z.string(), message: z.string() }),
        },
      },
    },
    async (request) => {
      const session = request.session!;
      const row = await db.query.credentials.findFirst({
        where: and(eq(credentials.userId, session.userId), eq(credentials.credentialId, request.params.credentialId)),
      });
      if (!row) {
        throw new ApiError(404, 'not-found', 'credential not found for this user');
      }
      if (row.removedAt) {
        return { ok: true as const, removedCurrentSession: false };
      }

      // Chain governs: verify the key is gone from the owner set everywhere it could be.
      let answered = 0;
      for (const chain of registry.all) {
        const isOwner = await isOwnerPublicKeyOnChain(
          chain.publicClient,
          row.walletAddress as `0x${string}`,
          row.publicKeyX as `0x${string}`,
          row.publicKeyY as `0x${string}`,
        );
        if (isOwner === true) {
          throw new ApiError(409, 'still-an-owner', `the key is still an owner of the wallet on chain ${chain.chainId} — remove it on-chain first`);
        }
        if (isOwner === false) answered += 1;
      }
      if (answered === 0) {
        throw new ApiError(409, 'unverifiable', 'no served chain could confirm the removal — try again once a chain is reachable');
      }

      const removedCurrentSession = row.id === session.credentialId;
      await db.update(credentials).set({ removedAt: new Date() }).where(eq(credentials.id, row.id));
      // WM-30/WM-31: a removed owner's sessions end now, not at their natural expiry.
      await sessions.revokeAllForCredential(row.id);
      await db.insert(walletManagementLog).values({
        tenantId: session.tenantId,
        userId: session.userId,
        sessionId: session.sessionId,
        walletAddress: row.walletAddress,
        action: 'owner-removed',
        outcome: 'ok',
        detail: {
          ownerKind: 'passkey',
          credentialId: row.credentialId,
          publicKeyX: row.publicKeyX,
          publicKeyY: row.publicKeyY,
          authorisedByCredential: session.credentialId,
          removedCurrentSession,
        },
      });
      app.metrics.walletManagement.inc({ action: 'owner-removed', outcome: 'ok', tenant: session.tenantId });
      return { ok: true as const, removedCurrentSession };
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
