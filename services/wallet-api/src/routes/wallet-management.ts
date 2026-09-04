import { randomBytes } from 'node:crypto';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { decodeClientDataJSON } from '@simplewebauthn/server/helpers';
import { and, count, eq, gt, sql } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import { credentials, pendingAdditions, walletManagementLog } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { ChallengeService } from '../services/challenges.js';
import type { ChainRegistry } from '../services/chains.js';
import { isOwnerPublicKeyOnChain } from '../services/owner-check.js';
import type { SessionContext } from '../services/sessions.js';
import { coseToXY } from './webauthn.js';

/**
 * The pending-addition lifecycle (D8, WM-18…WM-23) and the wallet-management audit trail
 * (WM-50, WM-51, WM-52).
 *
 * Nothing in this file changes an owner set. The slot is opened by the AUTHORISING device,
 * so its binding to tenant, user and wallet comes from an authenticated session (WM-19);
 * the claim code only routes a second device's ceremony to the right slot; a deposited
 * credential is inert; and the registry binds a credential to the wallet only at
 * consumption, AFTER the chain has confirmed the owner (WM-15) — verified here by reading
 * the account contract, never taken from the caller's word.
 */

/** Crockford base32 — no I, L, O, U, so a code survives being read aloud. */
const CLAIM_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateClaimCode(length = 8): string {
  const bytes = randomBytes(length);
  let code = '';
  for (let i = 0; i < length; i++) code += CLAIM_ALPHABET[bytes[i] % 32];
  return code;
}

/** Uppercases, strips separators and maps the confusable characters onto the alphabet. */
export function normaliseClaimCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V');
}

type PendingRow = typeof pendingAdditions.$inferSelect;

const errorResponseSchema = z.object({ error: z.string(), message: z.string() });

const pendingStatusSchema = z.object({
  id: z.string(),
  status: z.enum(['open', 'filled', 'consumed', 'declined', 'expired']),
  expiresAt: z.string(),
  /** Present once a second device deposited a key — what device A derives the fingerprint from. */
  publicKey: z.object({ x: z.string(), y: z.string() }).nullable(),
});

export default async function walletManagementRoutes(
  instance: FastifyInstance,
  opts: {
    db: Db;
    config: AppConfig;
    challenges: ChallengeService;
    registry: ChainRegistry;
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { db, config, challenges, registry } = opts;

  const audit = async (
    session: Pick<SessionContext, 'tenantId' | 'userId' | 'sessionId'> | { tenantId: string; userId: string | null; sessionId: null },
    walletAddress: string,
    action: string,
    outcome: 'ok' | 'refused',
    detail: Record<string, unknown> = {},
  ) => {
    await db.insert(walletManagementLog).values({
      tenantId: session.tenantId,
      userId: session.userId,
      sessionId: session.sessionId,
      walletAddress,
      action,
      outcome,
      detail,
    });
    app.metrics.walletManagement.inc({ action, outcome, tenant: session.tenantId });
  };

  /**
   * Lazily expires a slot whose deadline passed (WM-22): expiry is recorded when observed,
   * so a key offered and never signed for stays visible after the fact (WM-51).
   */
  const withExpiry = async (slot: PendingRow): Promise<PendingRow> => {
    if ((slot.status === 'open' || slot.status === 'filled') && slot.expiresAt.getTime() <= Date.now()) {
      await db.update(pendingAdditions).set({ status: 'expired' }).where(eq(pendingAdditions.id, slot.id));
      await audit(
        { tenantId: slot.tenantId, userId: slot.userId, sessionId: null },
        slot.walletAddress,
        'pending-expired',
        'ok',
        { pendingAdditionId: slot.id, hadCredential: !!slot.credentialId },
      );
      return { ...slot, status: 'expired' };
    }
    return slot;
  };

  /** WM-23: an expired, unknown or consumed slot is refused with a reason the user can act on. */
  const refuseDead = (slot: PendingRow): never => {
    if (slot.status === 'expired') {
      throw new ApiError(410, 'pending-expired', 'this pending addition has expired — start again and create a fresh passkey on the new device');
    }
    if (slot.status === 'consumed') {
      throw new ApiError(409, 'pending-consumed', 'this pending addition was already used');
    }
    if (slot.status === 'filled') {
      throw new ApiError(409, 'pending-already-filled', 'a credential was already deposited into this pending addition');
    }
    throw new ApiError(409, 'pending-declined', 'this pending addition was declined');
  };

  /** Resolves a slot owned by the calling session; unknown and foreign are indistinguishable (no oracle). */
  const ownSlot = async (request: FastifyRequest, id: string): Promise<PendingRow> => {
    const session = request.session!;
    const slot = await db.query.pendingAdditions.findFirst({ where: eq(pendingAdditions.id, id) });
    if (!slot || slot.userId !== session.userId || slot.tenantId !== session.tenantId || slot.walletAddress !== session.walletAddress) {
      throw new ApiError(404, 'pending-unknown', 'no such pending addition');
    }
    return withExpiry(slot);
  };

  const ceremonyRateLimit = {
    config: {
      rateLimit: {
        max: config.CEREMONY_RATE_LIMIT_PER_MINUTE,
        timeWindow: '1 minute',
        keyGenerator: (request: FastifyRequest) => `${request.tenant?.id ?? 'none'}:${request.ip}`,
      },
    },
  };

  // ── The authorising device's side ─────────────────────────────────────────────

  app.post(
    '/v1/wallet/pending-additions',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['wallet-management'],
        security: [{ session: [] }],
        response: {
          200: z.object({ id: z.string(), claimCode: z.string(), expiresAt: z.string() }),
          429: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const session = request.session!;
      // WM-19's per-user rate limit, as a cap on concurrently open slots: a claim code is
      // guessable in proportion to how many are outstanding, so the bound is on that.
      const [{ value: openCount }] = await db
        .select({ value: count() })
        .from(pendingAdditions)
        .where(
          and(
            eq(pendingAdditions.userId, session.userId),
            eq(pendingAdditions.status, 'open'),
            gt(pendingAdditions.expiresAt, sql`now()`),
          ),
        );
      if (openCount >= config.PENDING_ADDITION_MAX_OPEN_PER_USER) {
        return reply
          .code(429)
          .send({ error: 'too-many-pending', message: `at most ${config.PENDING_ADDITION_MAX_OPEN_PER_USER} pending additions may be open at once` });
      }

      const expiresAt = new Date(Date.now() + config.PENDING_ADDITION_TTL_SECONDS * 1000);
      const [slot] = await db
        .insert(pendingAdditions)
        .values({
          tenantId: session.tenantId,
          userId: session.userId,
          walletAddress: session.walletAddress,
          claimCode: generateClaimCode(),
          expiresAt,
        })
        .returning();
      await audit(session, session.walletAddress, 'pending-opened', 'ok', { pendingAdditionId: slot.id });
      return { id: slot.id, claimCode: slot.claimCode, expiresAt: expiresAt.toISOString() };
    },
  );

  app.get(
    '/v1/wallet/pending-additions/:id',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['wallet-management'],
        security: [{ session: [] }],
        params: z.object({ id: z.string().uuid() }),
        response: { 200: pendingStatusSchema, 404: errorResponseSchema },
      },
    },
    async (request) => {
      const slot = await ownSlot(request, request.params.id);
      return {
        id: slot.id,
        status: slot.status,
        expiresAt: slot.expiresAt.toISOString(),
        publicKey: slot.publicKeyX && slot.publicKeyY ? { x: slot.publicKeyX, y: slot.publicKeyY } : null,
      };
    },
  );

  /**
   * The user looked at the two fingerprints and they did NOT match — or declined for any
   * reason. Counted and alertable (WM-52): a declined fingerprint is either a bug or an
   * attempt at exactly the substitution D8 exists to prevent.
   */
  app.post(
    '/v1/wallet/pending-additions/:id/decline',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['wallet-management'],
        security: [{ session: [] }],
        params: z.object({ id: z.string().uuid() }),
        response: { 200: z.object({ ok: z.literal(true) }), 404: errorResponseSchema, 409: errorResponseSchema, 410: errorResponseSchema },
      },
    },
    async (request) => {
      const slot = await ownSlot(request, request.params.id);
      if (slot.status !== 'open' && slot.status !== 'filled') refuseDead(slot);
      await db.update(pendingAdditions).set({ status: 'declined' }).where(eq(pendingAdditions.id, slot.id));
      await audit(request.session!, slot.walletAddress, 'pending-declined', 'ok', {
        pendingAdditionId: slot.id,
        hadCredential: !!slot.credentialId,
      });
      return { ok: true as const };
    },
  );

  /**
   * Binds the deposited credential to the session's wallet — the LAST step, after the
   * chain already carries the owner (WM-15). The chain is not taken on trust: this reads
   * `isOwnerPublicKey(x, y)` from the account contract on the chains the caller says the
   * change was applied to, and refuses to bind unless at least one confirms it. A failure
   * between chain write and this call leaves an owner with no registry row, which the
   * interface renders honestly (WM-04) — never a registry row the chain does not back.
   */
  app.post(
    '/v1/wallet/pending-additions/:id/complete',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['wallet-management'],
        security: [{ session: [] }],
        params: z.object({ id: z.string().uuid() }),
        body: z.object({
          /** The served chains the owner change was submitted to and confirmed on. */
          chainIds: z.array(z.number().int().positive()).min(1),
          /** Initial name for the new credential (WM-07); the user can rename later. */
          name: z.string().max(256).optional(),
        }),
        response: {
          200: z.object({ ok: z.literal(true), credentialId: z.string() }),
          400: z.object({ error: z.string(), message: z.string(), servedChainIds: z.array(z.number()).optional() }),
          404: errorResponseSchema,
          409: errorResponseSchema,
          410: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const session = request.session!;
      const slot = await ownSlot(request, request.params.id);
      if (slot.status === 'open') {
        throw new ApiError(409, 'pending-not-filled', 'no credential has been deposited into this pending addition yet');
      }
      if (slot.status !== 'filled') refuseDead(slot);

      const served = registry.servedChainIds();
      const unknown = request.body.chainIds.filter((chainId) => !served.includes(chainId));
      if (unknown.length > 0) {
        return reply.code(400).send({ error: 'unknown-chain', message: `not served: ${unknown.join(', ')}`, servedChainIds: served });
      }

      // Chain governs (D1/WM-36): the registry asserts ownership only after the chain does.
      let confirmed = false;
      for (const chainId of request.body.chainIds) {
        const chain = registry.get(chainId);
        const isOwner = await isOwnerPublicKeyOnChain(
          chain.publicClient,
          session.walletAddress as `0x${string}`,
          slot.publicKeyX as `0x${string}`,
          slot.publicKeyY as `0x${string}`,
        );
        if (isOwner === true) {
          confirmed = true;
          break;
        }
      }
      if (!confirmed) {
        await audit(session, session.walletAddress, 'binding-refused', 'refused', {
          pendingAdditionId: slot.id,
          reason: 'not-an-owner-on-chain',
          chainIds: request.body.chainIds,
        });
        throw new ApiError(409, 'not-an-owner-on-chain', 'the deposited key is not an owner of this wallet on any named chain — the registry binds only after the chain confirms');
      }

      const [credential] = await db.transaction(async (tx) => {
        const inserted = await tx
          .insert(credentials)
          .values({
            tenantId: session.tenantId,
            userId: session.userId,
            rpId: request.tenant!.rpId,
            credentialId: slot.credentialId!,
            cosePublicKey: slot.cosePublicKey!,
            publicKeyX: slot.publicKeyX!,
            publicKeyY: slot.publicKeyY!,
            transports: slot.transports ?? [],
            // WM-15: BOUND to the wallet the session already controls — never derived from
            // the new key, which would name a different wallet.
            walletAddress: session.walletAddress,
            name: request.body.name ?? null,
          })
          .returning();
        await tx.update(pendingAdditions).set({ status: 'consumed', consumedAt: sql`now()` }).where(eq(pendingAdditions.id, slot.id));
        return inserted;
      });

      await audit(session, session.walletAddress, 'pending-consumed', 'ok', { pendingAdditionId: slot.id });
      await audit(session, session.walletAddress, 'owner-added', 'ok', {
        ownerKind: 'passkey',
        publicKeyX: slot.publicKeyX,
        publicKeyY: slot.publicKeyY,
        chainIds: request.body.chainIds,
        authorisedByCredential: session.credentialId,
      });
      return { ok: true as const, credentialId: credential.credentialId };
    },
  );

  // ── The new device's side (no session — the claim code only ROUTES, WM-19) ────

  /**
   * Resolves a claim code to a registration challenge for the new device. Deliberately
   * issues NO session and discloses only what the ceremony needs; the challenge is bound
   * to the slot's tenant and user, which the fill step enforces.
   */
  app.post(
    '/v1/wallet/pending-additions/claim',
    {
      ...ceremonyRateLimit,
      preHandler: app.requireTenant,
      schema: {
        tags: ['wallet-management'],
        body: z.object({ claimCode: z.string().min(4).max(32) }),
        response: {
          200: z.object({ rpId: z.string(), challenge: z.string(), pendingAdditionId: z.string() }),
          404: errorResponseSchema,
          409: errorResponseSchema,
          410: errorResponseSchema,
        },
      },
    },
    async (request) => {
      const tenant = request.tenant!;
      const code = normaliseClaimCode(request.body.claimCode);
      let slot = await db.query.pendingAdditions.findFirst({
        where: and(eq(pendingAdditions.claimCode, code), eq(pendingAdditions.tenantId, tenant.id)),
      });
      if (!slot) throw new ApiError(404, 'pending-unknown', 'no pending addition matches this code — check it and try again');
      slot = await withExpiry(slot);
      if (slot.status !== 'open') refuseDead(slot);

      const challenge = await challenges.issue('registration', slot.userId, tenant.id);
      return { rpId: tenant.rpId, challenge, pendingAdditionId: slot.id };
    },
  );

  /**
   * Deposits the newly created credential into the slot. The credential stays INERT: no
   * owner is added, no session granted — the slot now merely carries a public key for the
   * authorising device to display, compare and (only if the user confirms the fingerprint)
   * sign for (WM-20, WM-21).
   */
  app.post(
    '/v1/wallet/pending-additions/claim/fill',
    {
      ...ceremonyRateLimit,
      preHandler: app.requireTenant,
      schema: {
        tags: ['wallet-management'],
        body: z.object({
          claimCode: z.string().min(4).max(32),
          response: z
            .object({
              id: z.string(),
              rawId: z.string(),
              type: z.literal('public-key'),
              response: z
                .object({
                  clientDataJSON: z.string(),
                  attestationObject: z.string(),
                  transports: z.array(z.string()).optional(),
                })
                .passthrough(),
              clientExtensionResults: z.record(z.unknown()).default({}),
              authenticatorAttachment: z.string().optional(),
            })
            .passthrough(),
        }),
        response: {
          200: z.object({ ok: z.literal(true), publicKey: z.object({ x: z.string(), y: z.string() }) }),
          400: errorResponseSchema,
          404: errorResponseSchema,
          409: errorResponseSchema,
          410: errorResponseSchema,
        },
      },
    },
    async (request) => {
      const tenant = request.tenant!;
      const code = normaliseClaimCode(request.body.claimCode);
      let slot = await db.query.pendingAdditions.findFirst({
        where: and(eq(pendingAdditions.claimCode, code), eq(pendingAdditions.tenantId, tenant.id)),
      });
      if (!slot) throw new ApiError(404, 'pending-unknown', 'no pending addition matches this code — check it and try again');
      slot = await withExpiry(slot);
      if (slot.status !== 'open') refuseDead(slot);

      const { response } = request.body;
      let challenge: string;
      try {
        challenge = decodeClientDataJSON(response.response.clientDataJSON).challenge;
      } catch {
        throw new ApiError(400, 'bad-client-data', 'clientDataJSON could not be decoded');
      }
      const consumed = await challenges.consume(challenge, 'registration');
      // The challenge was issued by the claim step, bound to the slot's tenant and user —
      // enforcing those bindings is what stops a challenge minted elsewhere filling a slot.
      if (!consumed || consumed.tenantId !== tenant.id || consumed.userId !== slot.userId) {
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: response as unknown as RegistrationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: tenant.expectedOrigins,
          expectedRPID: tenant.rpId,
          requireUserVerification: false,
        });
      } catch (error) {
        throw new ApiError(400, 'verification-failed', (error as Error).message);
      }
      if (!verification.verified || !verification.registrationInfo) {
        throw new ApiError(400, 'verification-failed', 'registration response could not be verified');
      }

      const info = verification.registrationInfo;
      const { x, y } = coseToXY(info.credential.publicKey);
      const updated = await db
        .update(pendingAdditions)
        .set({
          status: 'filled',
          filledAt: sql`now()`,
          credentialId: info.credential.id,
          cosePublicKey: Buffer.from(info.credential.publicKey),
          publicKeyX: x,
          publicKeyY: y,
          transports: info.credential.transports ?? response.response.transports ?? [],
        })
        // Guarded re-check of status: two concurrent fills of one slot must not both win.
        .where(and(eq(pendingAdditions.id, slot.id), eq(pendingAdditions.status, 'open')))
        .returning({ id: pendingAdditions.id });
      if (updated.length === 0) {
        throw new ApiError(409, 'pending-consumed', 'this pending addition was already filled');
      }

      await audit({ tenantId: slot.tenantId, userId: slot.userId, sessionId: null }, slot.walletAddress, 'pending-filled', 'ok', {
        pendingAdditionId: slot.id,
      });
      return { ok: true as const, publicKey: { x, y } };
    },
  );

  // ── Audit of owner changes made without registry involvement ──────────────────

  /**
   * Records owner-set changes the registry has no row for — an externally-owned account
   * added or removed (WM-24), or an owner added outside this deployment being removed. The
   * transactions themselves are audited by userop_log; this keeps the management trail
   * complete (WM-50). Nothing here grants anything: it is an audit write, scoped to the
   * session's own wallet.
   */
  app.post(
    '/v1/wallet/owner-events',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['wallet-management'],
        security: [{ session: [] }],
        body: z.object({
          action: z.enum(['owner-added', 'owner-removed', 'owner-change-refused']),
          ownerKind: z.enum(['address', 'passkey']),
          /** The owner bytes or address the change concerned. */
          owner: z.string().max(200),
          chainIds: z.array(z.number().int().positive()).max(32).default([]),
          detail: z.string().max(1000).optional(),
        }),
        response: { 200: z.object({ ok: z.literal(true) }) },
      },
    },
    async (request) => {
      const session = request.session!;
      const { action, ownerKind, owner, chainIds, detail } = request.body;
      await audit(session, session.walletAddress, action, action === 'owner-change-refused' ? 'refused' : 'ok', {
        ownerKind,
        owner,
        chainIds,
        detail,
        authorisedByCredential: session.credentialId,
      });
      return { ok: true as const };
    },
  );
}
