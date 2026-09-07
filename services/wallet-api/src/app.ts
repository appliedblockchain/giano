import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';
import { jsonSchemaTransform, serializerCompiler, validatorCompiler, type ZodTypeProvider } from 'fastify-type-provider-zod';
import { createPublicClient, http } from 'viem';
import type { AppConfig } from './config.js';
import type { Db } from './db/index.js';
import authPlugin from './plugins/auth.js';
import errorHandler from './plugins/error-handler.js';
import metricsPlugin from './plugins/metrics.js';
import tenantPlugin from './plugins/tenant.js';
import adminRoutes from './routes/admin.js';
import credentialRoutes from './routes/credentials.js';
import healthRoutes from './routes/health.js';
import useropRoutes from './routes/userops.js';
import webauthnRoutes from './routes/webauthn.js';
import wellKnownRoutes from './routes/well-known.js';
import { createBundlerService } from './services/bundler.js';
import { createChallengeService } from './services/challenges.js';
import { createSessionService } from './services/sessions.js';
import { createTenantService } from './services/tenants.js';

export type BuildAppOptions = {
  config: AppConfig;
  db: Db;
  /** Overridable in tests. */
  fetchImpl?: typeof fetch;
};

/**
 * Design constraint: buildApp must never READ the tenants table — tenant resolution is
 * strictly per-request (plugins/tenant.ts), so tenants seeded or edited after boot are
 * live immediately and openapi/generate.ts can build the app without a database.
 */
export async function buildApp({ config, db, fetchImpl }: BuildAppOptions) {
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
  const bundler = createBundlerService(config.BUNDLER_URL, config.ENTRYPOINT_ADDRESS, fetchImpl);
  const publicClient = createPublicClient({ transport: http(config.RPC_URL) });
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
        description: 'WebAuthn ceremonies, sessions and policied ERC-4337 user-operation relay for Giano smart wallets (multi-tenant).',
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

  await app.register(healthRoutes, { db, version: process.env.GIANO_VERSION ?? '0.1.0', chainId: config.CHAIN_ID });
  await app.register(wellKnownRoutes, { db });
  await app.register(adminRoutes, { db });
  await app.register(webauthnRoutes, { db, config, challenges, sessions, publicClient });
  await app.register(credentialRoutes, { db, sessions });
  await app.register(useropRoutes, {
    db,
    config,
    bundler,
    // deployment-wide defaults; tenants.policy overrides per field (mergePolicy)
    defaultPolicy: {
      maxCallGas: config.USEROP_MAX_CALL_GAS,
      maxVerificationGas: config.USEROP_MAX_VERIFICATION_GAS,
      maxFeePerGas: config.USEROP_MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: config.USEROP_MAX_PRIORITY_FEE_PER_GAS,
      allowedTargets: config.USEROP_ALLOWED_TARGETS,
      allowedPaymasters: config.USEROP_ALLOWED_PAYMASTERS,
    },
  });

  return app;
}
