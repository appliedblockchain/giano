import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { cose, decodeClientDataJSON, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { Hex, PublicClient } from 'viem';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import { credentials, users } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { ChallengeService } from '../services/challenges.js';
import type { SessionService } from '../services/sessions.js';
import { computeWalletAddress } from '../services/wallet-address.js';

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

function extractChallenge(clientDataJSONb64: string): string {
  try {
    return decodeClientDataJSON(clientDataJSONb64).challenge;
  } catch {
    throw new ApiError(400, 'bad-client-data', 'clientDataJSON could not be decoded');
  }
}

function coseToXY(cosePublicKey: Uint8Array): { x: Hex; y: Hex } {
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
    publicClient: PublicClient;
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { db, config, challenges, sessions } = opts;

  const rateLimit = {
    config: {
      rateLimit: { max: config.CEREMONY_RATE_LIMIT_PER_MINUTE, timeWindow: '1 minute' },
    },
  };

  /**
   * Issues a ceremony challenge plus the user's known credential ids. Guarded: in
   * production (OPEN_REGISTRATION=false) this requires an admin API key so the client
   * project's backend binds registration to its own authentication; identity never
   * comes from the browser unauthenticated.
   */
  app.post(
    '/v1/webauthn/options',
    {
      ...rateLimit,
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
          401: z.object({ error: z.string(), message: z.string() }),
        },
      },
    },
    async (request, reply) => {
      if (!config.OPEN_REGISTRATION && !app.isAdminRequest(request)) {
        return reply.code(401).send({ error: 'unauthorized', message: 'registration options require an admin API key (OPEN_REGISTRATION=false)' });
      }
      const { externalUserId, kind } = request.body;
      const user = await db.query.users.findFirst({ where: eq(users.externalId, externalUserId) });
      const creds = user ? await db.select({ credentialId: credentials.credentialId }).from(credentials).where(eq(credentials.userId, user.id)) : [];
      const resolvedKind = kind === 'auto' ? (creds.length > 0 ? 'authentication' : 'registration') : kind;
      const challenge = await challenges.issue(resolvedKind, user?.id ?? null);
      return {
        kind: resolvedKind,
        challenge,
        rpId: config.RP_ID,
        userExists: !!user,
        credentialIds: creds.map((c) => c.credentialId),
      };
    },
  );

  app.post(
    '/v1/webauthn/registration/verify',
    {
      ...rateLimit,
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
        },
      },
    },
    async (request) => {
      const { externalUserId, response } = request.body;

      const challenge = extractChallenge(response.response.clientDataJSON);
      const consumed = await challenges.consume(challenge, 'registration');
      if (!consumed) {
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: response as unknown as RegistrationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: config.EXPECTED_ORIGINS,
          expectedRPID: config.RP_ID,
          requireUserVerification: false,
        });
      } catch (error) {
        throw new ApiError(400, 'verification-failed', (error as Error).message);
      }
      if (!verification.verified || !verification.registrationInfo) {
        app.metrics.ceremonyFailures.inc({ kind: 'registration' });
        throw new ApiError(400, 'verification-failed', 'registration response could not be verified');
      }

      const info = verification.registrationInfo;
      const { x, y } = coseToXY(info.credential.publicKey);
      const walletAddress = await computeWalletAddress(opts.publicClient, config.FACTORY_ADDRESS, x, y);

      const result = await db.transaction(async (tx) => {
        const [user] = await tx
          .insert(users)
          .values({ externalId: externalUserId })
          .onConflictDoUpdate({ target: users.externalId, set: { externalId: externalUserId } })
          .returning();
        const [credential] = await tx
          .insert(credentials)
          .values({
            userId: user.id,
            credentialId: info.credential.id,
            cosePublicKey: Buffer.from(info.credential.publicKey),
            publicKeyX: x,
            publicKeyY: y,
            counter: BigInt(info.credential.counter),
            transports: info.credential.transports ?? response.response.transports ?? [],
            walletAddress,
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
        },
      },
    },
    async (request) => {
      const { response } = request.body;

      const challenge = extractChallenge(response.response.clientDataJSON);
      const consumed = await challenges.consume(challenge, 'authentication');
      if (!consumed) {
        throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
      }

      const credential = await db.query.credentials.findFirst({ where: eq(credentials.credentialId, response.id) });
      if (!credential) {
        throw new ApiError(400, 'unknown-credential', 'credential is not registered');
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: response as unknown as AuthenticationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: config.EXPECTED_ORIGINS,
          expectedRPID: config.RP_ID,
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
        app.metrics.ceremonyFailures.inc({ kind: 'authentication' });
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
