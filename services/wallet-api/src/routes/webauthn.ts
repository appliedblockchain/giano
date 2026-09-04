import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { cose, decodeClientDataJSON, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { and, eq, isNull } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { Hex } from 'viem';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import { credentials, users } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { ChallengeService } from '../services/challenges.js';
import type { SessionService } from '../services/sessions.js';
import { computeWalletAddress } from '../services/wallet-address.js';
import type { ChainRegistry } from '../services/chains.js';

const registrationResponseSchema = z
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
  .passthrough();

const authenticationResponseSchema = z
  .object({
    id: z.string(),
    rawId: z.string(),
    type: z.literal('public-key'),
    response: z
      .object({
        clientDataJSON: z.string(),
        authenticatorData: z.string(),
        signature: z.string(),
        userHandle: z.string().optional(),
      })
      .passthrough(),
    clientExtensionResults: z.record(z.unknown()).default({}),
    authenticatorAttachment: z.string().optional(),
  })
  .passthrough();

const sessionResponseSchema = z.object({
  token: z.string(),
  expiresAt: z.string(),
});

const errorResponseSchema = z.object({ error: z.string(), message: z.string() });

function extractChallenge(clientDataJSONb64: string): string {
  try {
    return decodeClientDataJSON(clientDataJSONb64).challenge;
  } catch {
    throw new ApiError(400, 'bad-client-data', 'clientDataJSON could not be decoded');
  }
}

export function coseToXY(cosePublicKey: Uint8Array): { x: Hex; y: Hex } {
  const decoded = decodeCredentialPublicKey(cosePublicKey);
  if (!cose.isCOSEPublicKeyEC2(decoded)) {
    throw new ApiError(400, 'unsupported-key', 'only EC2 (P-256) credentials are supported');
  }
  const x = decoded.get(cose.COSEKEYS.x);
  const y = decoded.get(cose.COSEKEYS.y);
  if (!x || !y || x.length !== 32 || y.length !== 32) {
    throw new ApiError(400, 'unsupported-key', 'credential public key is missing P-256 coordinates');
  }
  const hex = (bytes: Uint8Array): Hex => `0x${Buffer.from(bytes).toString('hex')}` as Hex;
  return { x: hex(x), y: hex(y) };
}

export default async function webauthnRoutes(
  instance: FastifyInstance,
  opts: {
    db: Db;
    config: AppConfig;
    challenges: ChallengeService;
    sessions: SessionService;
    registry: ChainRegistry;
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { db, config, challenges, sessions } = opts;

  // Every ceremony route resolves its tenant from the Origin header (fail closed) —
  // WebAuthn corroborates it: clientDataJSON.origin must match the resolved tenant's
  // expected_origins or verification fails.
  const rateLimit = {
    config: {
      rateLimit: {
        max: config.CEREMONY_RATE_LIMIT_PER_MINUTE,
        timeWindow: '1 minute',
        // per tenant + IP, so one tenant's traffic cannot starve another's ceremonies
        keyGenerator: (request: FastifyRequest) => `${request.tenant?.id ?? 'none'}:${request.ip}`,
      },
    },
  };

  /**
   * Issues a ceremony challenge plus the user's known credential ids. Guarded: when the
   * tenant has open_registration=false this requires the TENANT'S OWN admin API key, so
   * the client project's backend binds registration to its own authentication; identity
   * never comes from the browser unauthenticated.
   */
  app.post(
    '/v1/webauthn/options',
    {
      ...rateLimit,
      preHandler: app.requireTenant,
      schema: {
        tags: ['webauthn'],
        body: z.object({
          externalUserId: z.string().min(1).max(256),
          kind: z.enum(['auto', 'registration', 'authentication']).default('auto'),
        }),
        response: {
          200: z.object({
            kind: z.enum(['registration', 'authentication']),
            challenge: z.string(),
            rpId: z.string(),
            userExists: z.boolean(),
            credentialIds: z.array(z.string()),
          }),
          401: errorResponseSchema,
          403: errorResponseSchema,
        },
      },
    },
    async (request, reply) => {
      const tenant = request.tenant!;
      if (!tenant.openRegistration) {
        const admin = await app.resolveAdminTenant(request);
        if (!admin || admin.id !== tenant.id) {
          return reply
            .code(401)
            .send({ error: 'unauthorized', message: "registration options require the tenant's admin API key (open_registration is false)" });
        }
      }
      const { externalUserId, kind } = request.body;
      const user = await db.query.users.findFirst({ where: and(eq(users.tenantId, tenant.id), eq(users.externalId, externalUserId)) });
      // Removed credentials are excluded: offering one for sign-in would raise a passkey
      // prompt that can only end in a WM-31 refusal.
      const creds = user
        ? await db
            .select({ credentialId: credentials.credentialId })
            .from(credentials)
            .where(and(eq(credentials.userId, user.id), isNull(credentials.removedAt)))
        : [];
      const resolvedKind = kind === 'auto' ? (creds.length > 0 ? 'authentication' : 'registration') : kind;
      const challenge = await challenges.issue(resolvedKind, user?.id ?? null, tenant.id);
      return {
        kind: resolvedKind,
        challenge,
        rpId: tenant.rpId,
        userExists: !!user,
        credentialIds: creds.map((c) => c.credentialId),
      };
    },
  );

  app.post(
    '/v1/webauthn/registration/verify',
    {
      ...rateLimit,
      preHandler: app.requireTenant,
      schema: {
        tags: ['webauthn'],
        body: z.object({
          externalUserId: z.string().min(1).max(256),
          credentialName: z.string().max(256).optional(),
          response: registrationResponseSchema,
        }),
        response: {
          200: z.object({
            verified: z.literal(true),
            walletAddress: z.string(),
            credentialId: z.string(),
            session: sessionResponseSchema,
          }),
          403: errorResponseSchema,
        },
      },
    },
    async (request) => {
      const tenant = request.tenant!;
      const { externalUserId, credentialName, response } = request.body;

      const challenge = extractChallenge(response.response.clientDataJSON);
      const consumed = await challenges.consume(challenge, 'registration');
      if (!consumed) {
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }
      // C3: enforce the consumed challenge's bindings instead of trusting the body.
      // Cross-tenant redemption is indistinguishable from an unknown challenge (no oracle).
      if (consumed.tenantId !== tenant.id) {
        request.log.warn({ alert: 'cross-tenant-challenge', challengeTenant: consumed.tenantId }, 'challenge redeemed on a foreign tenant origin');
        app.metrics.crossTenantRejections.inc({ tenant: tenant.slug, kind: 'challenge' });
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }
      if (consumed.userId) {
        const boundUser = await db.query.users.findFirst({ where: eq(users.id, consumed.userId) });
        if (!boundUser || boundUser.tenantId !== tenant.id || boundUser.externalId !== externalUserId) {
          throw new ApiError(400, 'challenge-user-mismatch', 'challenge was issued for a different user');
        }
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
        app.metrics.ceremonyFailures.inc({ kind: 'registration', tenant: tenant.slug });
        throw new ApiError(400, 'verification-failed', 'registration response could not be verified');
      }

      const info = verification.registrationInfo;
      const { x, y } = coseToXY(info.credential.publicKey);
      // The wallet address is obtained from a served chain's own factory (MC-22). ANY ready
      // chain answers identically: the derivation has no chain-dependent term (MC-18), the
      // factory sits at the canonical address on every served chain (MC-19, verified at
      // boot), and exactly ONE address is stored per credential (MC-24) — the schema cannot
      // even represent a per-chain answer.
      const derivation = opts.registry.anyReady();
      const walletAddress = await computeWalletAddress(derivation.publicClient, derivation.factory, x, y);

      const result = await db.transaction(async (tx) => {
        // C1: get-or-create is scoped by (tenant_id, external_id) — two tenants using
        // the same external id are two distinct users with two distinct wallets.
        const [user] = await tx
          .insert(users)
          .values({ tenantId: tenant.id, externalId: externalUserId })
          .onConflictDoUpdate({ target: [users.tenantId, users.externalId], set: { externalId: externalUserId } })
          .returning();
        const [credential] = await tx
          .insert(credentials)
          .values({
            tenantId: tenant.id,
            rpId: tenant.rpId,
            userId: user.id,
            credentialId: info.credential.id,
            cosePublicKey: Buffer.from(info.credential.publicKey),
            publicKeyX: x,
            publicKeyY: y,
            counter: BigInt(info.credential.counter),
            transports: info.credential.transports ?? response.response.transports ?? [],
            walletAddress,
            // WM-08: persisted as the credential's initial name rather than dropped. A name is
            // a local label only — never an input to any decision (WM-11).
            name: credentialName ?? null,
          })
          .returning();
        return { user, credential };
      });

      const session = await sessions.create(result.user.id, result.credential.id);
      return {
        verified: true as const,
        walletAddress,
        credentialId: result.credential.credentialId,
        session: { token: session.token, expiresAt: session.expiresAt.toISOString() },
      };
    },
  );

  app.post(
    '/v1/webauthn/authentication/verify',
    {
      ...rateLimit,
      preHandler: app.requireTenant,
      schema: {
        tags: ['webauthn'],
        body: z.object({ response: authenticationResponseSchema }),
        response: {
          200: z.object({
            verified: z.literal(true),
            walletAddress: z.string(),
            credentialId: z.string(),
            externalUserId: z.string(),
            session: sessionResponseSchema,
          }),
          403: errorResponseSchema,
        },
      },
    },
    async (request) => {
      const tenant = request.tenant!;
      const { response } = request.body;

      const challenge = extractChallenge(response.response.clientDataJSON);
      const consumed = await challenges.consume(challenge, 'authentication');
      if (!consumed) {
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }
      if (consumed.tenantId !== tenant.id) {
        request.log.warn({ alert: 'cross-tenant-challenge', challengeTenant: consumed.tenantId }, 'challenge redeemed on a foreign tenant origin');
        app.metrics.crossTenantRejections.inc({ tenant: tenant.slug, kind: 'challenge' });
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }

      // C2: resolve globally by credential id, then tenant-check explicitly. The global
      // lookup is deliberate — it makes the rejection ALERTABLE: distinct RP IDs mean
      // this branch is unreachable through a browser, so if it ever fires, RP resolution
      // is broken or someone is probing. Externally identical to unknown-credential.
      let credential = await db.query.credentials.findFirst({ where: eq(credentials.credentialId, response.id) });
      if (credential && credential.tenantId !== tenant.id) {
        request.log.error(
          { alert: 'cross-tenant-credential', credentialTenant: credential.tenantId },
          'credential replayed across tenants — RP resolution broken or a probe',
        );
        app.metrics.crossTenantRejections.inc({ tenant: tenant.slug, kind: 'credential' });
        credential = undefined;
      }
      if (!credential) {
        throw new ApiError(400, 'unknown-credential', 'credential is not registered');
      }
      // WM-31: a removed owner still exists on the user's device — it can only be refused,
      // and it must be refused with a reason that says WHY, distinguishable from a generic
      // failure. The refusal happens BEFORE issuing anything, not at on-chain signature
      // verification, which is the least legible place for it to fail.
      if (credential.removedAt) {
        throw new ApiError(403, 'credential-removed', 'this passkey is no longer an owner of the wallet — sign in with a different passkey');
      }
      // C3: an options call for a known user binds the challenge to that user
      if (consumed.userId && consumed.userId !== credential.userId) {
        throw new ApiError(400, 'challenge-user-mismatch', 'challenge was issued for a different user');
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: response as unknown as AuthenticationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: tenant.expectedOrigins,
          expectedRPID: tenant.rpId,
          credential: {
            id: credential.credentialId,
            publicKey: new Uint8Array(credential.cosePublicKey),
            counter: Number(credential.counter),
            transports: (credential.transports ?? undefined) as never,
          },
          requireUserVerification: false,
        });
      } catch (error) {
        throw new ApiError(400, 'verification-failed', (error as Error).message);
      }
      if (!verification.verified) {
        app.metrics.ceremonyFailures.inc({ kind: 'authentication', tenant: tenant.slug });
        throw new ApiError(400, 'verification-failed', 'authentication response could not be verified');
      }

      // Counter regression check: many passkey providers always report 0, so the
      // regression rule only applies when the authenticator actually increments.
      const newCounter = BigInt(verification.authenticationInfo.newCounter);
      if (newCounter > 0n && credential.counter > 0n && newCounter <= credential.counter) {
        throw new ApiError(400, 'counter-regression', 'authenticator counter regressed — possible cloned credential');
      }
      if (newCounter > credential.counter) {
        await db.update(credentials).set({ counter: newCounter }).where(eq(credentials.id, credential.id));
      }

      const user = await db.query.users.findFirst({ where: eq(users.id, credential.userId) });
      const session = await sessions.create(credential.userId, credential.id);
      return {
        verified: true as const,
        walletAddress: credential.walletAddress,
        credentialId: credential.credentialId,
        externalUserId: user!.externalId,
        session: { token: session.token, expiresAt: session.expiresAt.toISOString() },
      };
    },
  );
}
