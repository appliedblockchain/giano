import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import { platformAdminInputSchema, type PlatformAdmin, type PlatformAdminService } from '../services/platform-admins.js';
import { TenantWriteError } from '../services/tenants.js';

const HISTORY_LIMIT = 100;

const errorSchema = z.object({ error: z.string(), message: z.string() }).passthrough();
const errors = { 400: errorSchema, 401: errorSchema, 404: errorSchema, 409: errorSchema };

const adminSchema = z.object({ id: z.string(), address: z.string(), addedBy: z.string(), createdAt: z.string() });
const adminView = (row: PlatformAdmin) => ({ id: row.id, address: row.address, addedBy: row.addedBy, createdAt: row.createdAt.toISOString() });

function sendWriteError(reply: FastifyReply, error: unknown) {
  if (!(error instanceof TenantWriteError)) throw error;
  return reply.code(error.status).send({ error: error.code, message: error.message, ...error.detail });
}

/**
 * The platform admins themselves (specs/PLATFORM-ADMIN-SPECS.md §4.1): list, add, remove and history.
 * Registered with the rest of the platform tier. Every route needs a platform admin session, refuses an
 * Origin, and is rate limited per session. Removing the last platform admin, or yourself, is refused.
 */
export default async function platformAdminRoutes(instance: FastifyInstance, opts: { admins: PlatformAdminService; config: AppConfig }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  app.addHook('onRequest', app.requirePlatformAdmin);

  const route = {
    config: {
      rateLimit: {
        max: opts.config.PLATFORM_RATE_LIMIT_PER_MINUTE,
        timeWindow: '1 minute',
        keyGenerator: (request: FastifyRequest) => `platform-session:${request.platformAdmin?.sessionId ?? 'none'}`,
      },
    },
  };
  const docs = { tags: ['platform'], security: [{ platformSession: [] }] };

  app.get(
    '/v1/platform/admins',
    { ...route, schema: { ...docs, summary: 'The platform admins, oldest first', response: { 200: z.object({ admins: z.array(adminSchema) }), ...errors } } },
    async () => ({ admins: (await opts.admins.list()).map(adminView) }),
  );

  app.post(
    '/v1/platform/admins',
    {
      ...route,
      schema: { ...docs, summary: 'Add a platform admin; they can sign in at once', body: platformAdminInputSchema, response: { 201: adminSchema, ...errors } },
    },
    async (request, reply) => {
      try {
        const row = await opts.admins.add(request.body, request.platformAdmin!);
        request.log.info({ adminId: row.id }, 'platform admin added');
        return reply.code(201).send(adminView(row));
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.delete(
    '/v1/platform/admins/:id',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Remove a platform admin and end their sessions; never the last one, never yourself',
        params: z.object({ id: z.string().min(1).max(64) }),
        response: { 204: z.null(), ...errors },
      },
    },
    async (request, reply) => {
      try {
        await opts.admins.remove(request.params.id, request.platformAdmin!);
        request.log.info({ adminId: request.params.id }, 'platform admin removed');
        return reply.code(204).send(null);
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.get(
    '/v1/platform/admins/history',
    {
      ...route,
      schema: {
        ...docs,
        summary: `Every change to the platform admins, newest first, the latest ${HISTORY_LIMIT}`,
        response: {
          200: z.object({
            entries: z.array(z.object({ id: z.string(), adminId: z.string(), address: z.string(), action: z.string(), actor: z.string(), createdAt: z.string() })),
          }),
          ...errors,
        },
      },
    },
    async () => ({
      entries: (await opts.admins.history(HISTORY_LIMIT)).map((row) => ({
        id: row.id,
        adminId: row.adminId,
        address: row.address,
        action: row.action,
        actor: row.actor,
        createdAt: row.createdAt.toISOString(),
      })),
    }),
  );
}
