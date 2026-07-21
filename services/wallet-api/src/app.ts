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
import adminRoutes from './routes/admin.js';
import credentialRoutes from './routes/credentials.js';
import healthRoutes from './routes/health.js';
import useropRoutes from './routes/userops.js';
import webauthnRoutes from './routes/webauthn.js';
import wellKnownRoutes from './routes/well-known.js';
import { createBundlerService } from './services/bundler.js';
import { createChallengeService } from './services/challenges.js';
import { createSessionService } from './services/sessions.js';

export type BuildAppOptions = {
  config: AppConfig;
  db: Db;
  /** Overridable in tests. */
  fetchImpl?: typeof fetch;
};

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

  await app.register(errorHandler);
  await app.register(rateLimit, { global: false });
  if (config.CORS_ORIGINS.length > 0) {
    await app.register(cors, { origin: config.CORS_ORIGINS, credentials: true });
  }

  await app.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'Giano Wallet API',
        description: 'WebAuthn ceremonies, sessions and policied ERC-4337 user-operation relay for Giano smart wallets.',
        version: '1.0.0',
      },
      components: {
        securitySchemes: {
          session: { type: 'http', scheme: 'bearer', description: 'Opaque session token from a ceremony verify endpoint' },
          adminKey: { type: 'http', scheme: 'bearer', description: 'Admin API key (ADMIN_API_KEYS)' },
        },
      },
    },
    transform: jsonSchemaTransform,
  });
  if (config.NODE_ENV !== 'production') {
    await app.register(swaggerUi, { routePrefix: '/docs' });
  }

  await app.register(authPlugin, { sessions, adminApiKeys: config.ADMIN_API_KEYS });

  await app.register(healthRoutes, { db });
  await app.register(wellKnownRoutes, { db });
  await app.register(adminRoutes, { db });
  await app.register(webauthnRoutes, { db, config, challenges, sessions, publicClient });
  await app.register(credentialRoutes, { db, sessions });
  await app.register(useropRoutes, {
    db,
    config,
    bundler,
    policy: {
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
