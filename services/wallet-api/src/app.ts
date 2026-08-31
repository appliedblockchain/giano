import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';
import { jsonSchemaTransform, serializerCompiler, validatorCompiler, type ZodTypeProvider } from 'fastify-type-provider-zod';
import type { AppConfig } from './config.js';
import type { Db } from './db/index.js';
import authPlugin from './plugins/auth.js';
import chainPlugin from './plugins/chain.js';
import errorHandler from './plugins/error-handler.js';
import metricsPlugin from './plugins/metrics.js';
import tenantPlugin from './plugins/tenant.js';
import adminRoutes from './routes/admin.js';
import adminSponsorshipRoutes from './routes/admin-sponsorship.js';
import paymasterRoutes from './routes/paymaster.js';
import credentialRoutes from './routes/credentials.js';
import healthRoutes from './routes/health.js';
import useropRoutes from './routes/userops.js';
import webauthnRoutes from './routes/webauthn.js';
import wellKnownRoutes from './routes/well-known.js';
import { buildChainRegistry, type ChainRegistry } from './services/chains.js';
import { createChallengeService } from './services/challenges.js';
import { createSessionService } from './services/sessions.js';
import type { PaymasterReader } from './services/paymaster-contract.js';
import { createLedgerService } from './services/sponsorship-ledger.js';
import { createHsmSponsorshipSigner, createLocalSponsorshipSigner, type HsmSignerAdapter, type SponsorshipSigner } from './services/sponsorship-signer.js';
import { createTenantService } from './services/tenants.js';

export type BuildAppOptions = {
  config: AppConfig;
  db: Db;
  /** Overridable in tests. */
  fetchImpl?: typeof fetch;
  /**
   * Supplies the HSM-backed signer. Required when `SPONSORSHIP_SIGNER_KIND=hsm`, which `loadConfig`
   * forces for a production deployment — the deployment chooses its own key service (production
   * uses an AWS HSM through `evm-hsm-signer`), and the guarantee this codebase makes is only that
   * the key material never enters this process.
   */
  hsmSignerAdapter?: HsmSignerAdapter;
  /** Overridable in tests, so a sponsorship test needs no chain. Applied to every sponsoring chain. */
  paymasterReader?: PaymasterReader;
};

/**
 * Design constraint: buildApp must never READ the tenants table — tenant resolution is
 * strictly per-request (plugins/tenant.ts), so tenants seeded or edited after boot are
 * live immediately and openapi/generate.ts can build the app without a database. The same
 * holds for chains: the registry is CONSTRUCTED here (pure object wiring, no network);
 * verification against the chains themselves happens in index.ts before listen (§3.5).
 */
export async function buildApp({ config, db, fetchImpl, hsmSignerAdapter, paymasterReader }: BuildAppOptions) {
  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      ...(config.NODE_ENV === 'development' ? { transport: { target: 'pino-pretty' } } : {}),
    },
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const challenges = createChallengeService(db, config.CHALLENGE_TTL_SECONDS);
  const sessions = createSessionService(db, config.SESSION_TTL_SECONDS);
  const tenants = createTenantService(db);

  await app.register(errorHandler);
  await app.register(metricsPlugin, { bearerToken: config.METRICS_BEARER_TOKEN });
  await app.register(rateLimit, { global: false });
  // CORS is per-tenant and fail-closed: only origins listed in some tenant's
  // cors_origins (or a tenant wallet origin itself) receive ACAO headers. Server-side
  // authorization never relies on CORS — requireTenant/requireSession do the guarding.
  await app.register(cors, {
    credentials: true,
    origin: (origin, cb) => {
      if (!origin) return cb(null, false); // non-browser callers need no CORS
      tenants
        .isCorsOrigin(origin)
        .then((allowed) => cb(null, allowed))
        .catch((error) => cb(error as Error, false));
    },
  });

  await app.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'Giano Wallet API',
        description: 'WebAuthn ceremonies, sessions and policied ERC-4337 user-operation relay for Giano smart wallets (multi-tenant, multi-chain).',
        version: '1.0.0',
      },
      components: {
        securitySchemes: {
          session: { type: 'http', scheme: 'bearer', description: 'Opaque session token from a ceremony verify endpoint' },
          adminKey: { type: 'http', scheme: 'bearer', description: "Per-tenant admin API key (provisioned via TENANTS_SEED)" },
        },
      },
    },
    transform: jsonSchemaTransform,
  });
  if (config.NODE_ENV !== 'production') {
    await app.register(swaggerUi, { routePrefix: '/docs' });
  }

  await app.register(tenantPlugin, { tenants });
  await app.register(authPlugin, { sessions, tenants });

  // ── The chain registry ─────────────────────────────────────────────────────────
  //
  // One entry per configured chain, each holding its own read client, bundler, paymaster
  // reader and sponsorship service (MC-50). Sponsorship is off by default and wired only
  // when explicitly enabled, so a deployment that does not sponsor carries none of it:
  // no routes, no signer, no chain reads.
  const ledger = createLedgerService(db);
  const signer = config.SPONSORSHIP_ENABLED ? createSigner(config, hsmSignerAdapter) : undefined;
  const registry: ChainRegistry = buildChainRegistry({
    config,
    db,
    ledger,
    fetchImpl,
    signer,
    paymasterReader,
    onDecision: (chainId) => (event) => {
      // Slugs, not uuids, as metric labels: bounded cardinality and readable on a dashboard.
      // Resolving the slug is a lookup we deliberately skip here — the tenant id is already on
      // the log line, and a metric that needed a database read per increment would be a
      // liability on the hot path.
      app.metrics.sponsorshipDecisions.inc({
        tenant: event.tenantId,
        method: event.method,
        outcome: event.outcome,
        reason: event.reason ?? '',
        chain: String(chainId),
      });
      if (event.keyId) app.metrics.sponsorshipSignatures.inc({ tenant: event.tenantId, key_id: event.keyId, chain: String(chainId) });
      if (event.reason === 'temporarily-unavailable') app.metrics.sponsorshipUnavailable.inc({ cause: 'signer' });
    },
  });
  app.decorate('chains', registry);

  const sponsoringChains = registry.all.filter((chain) => chain.sponsorship);
  if (sponsoringChains.length > 0) {
    app.log.info(
      {
        chains: sponsoringChains.map((chain) => ({ chainId: chain.chainId, paymaster: chain.paymaster!.address })),
        signerKind: config.SPONSORSHIP_SIGNER_KIND,
        keyId: signer!.keyId,
      },
      'gas sponsorship enabled',
    );
  }

  await app.register(chainPlugin, { registry });

  await app.register(healthRoutes, {
    db,
    version: process.env.GIANO_VERSION ?? '0.1.0',
    registry,
    // The sponsorship service is on the critical path for transacting: if it cannot sign, this
    // deployment cannot sponsor, and reporting itself healthy would hide that. The signer is
    // shared, so asking any sponsoring chain answers for all of them (MC-72).
    sponsorshipHealth: sponsoringChains.length > 0 ? () => sponsoringChains[0].sponsorship!.health() : undefined,
  });
  await app.register(wellKnownRoutes, { db });
  await app.register(adminRoutes, { db });
  await app.register(adminSponsorshipRoutes, { db, config, ledger, registry });
  if (sponsoringChains.length > 0) {
    await app.register(paymasterRoutes, { config, registry });
  }
  await app.register(webauthnRoutes, { db, config, challenges, sessions, registry });
  await app.register(credentialRoutes, { db, sessions });
  await app.register(useropRoutes, {
    db,
    config,
    registry,
    // deployment-wide default caps; the chain descriptor's policy and tenants.policy
    // override per field, per chain (mergePolicy)
    defaultPolicy: {
      maxCallGas: config.USEROP_MAX_CALL_GAS,
      maxVerificationGas: config.USEROP_MAX_VERIFICATION_GAS,
      maxFeePerGas: config.USEROP_MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: config.USEROP_MAX_PRIORITY_FEE_PER_GAS,
    },
  });

  return app;
}

declare module 'fastify' {
  interface FastifyInstance {
    /** The chain registry — the only way this process reaches a chain (MC-96). */
    chains: ChainRegistry;
  }
}

/**
 * Builds the signer the deployment asked for.
 *
 * `local` is refused for a production deployment by `loadConfig`, not here, so that a
 * misconfiguration fails at boot with a legible message rather than at the first sponsorship
 * request.
 */
function createSigner(config: AppConfig, adapter?: HsmSignerAdapter): SponsorshipSigner {
  if (config.SPONSORSHIP_SIGNER_KIND === 'hsm') {
    if (!adapter) {
      throw new Error(
        'SPONSORSHIP_SIGNER_KIND=hsm requires an HSM signer adapter to be passed to buildApp. ' +
          'The key service is the deployment\'s choice — production uses an AWS HSM through evm-hsm-signer; ' +
          'this codebase only guarantees the key never enters the process.',
      );
    }
    return createHsmSponsorshipSigner(adapter);
  }
  return createLocalSponsorshipSigner(config.SPONSORSHIP_SIGNER_KEY_REF as `0x${string}`, 'local-dev');
}
