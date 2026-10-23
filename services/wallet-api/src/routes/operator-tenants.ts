import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import type { ChainRegistry } from '../services/chains.js';
import { createTenantAdminService } from '../services/tenant-admin.js';
import { IMMUTABLE_TENANT_FIELDS, tenantCreateSchema, tenantPatchSchema, TenantWriteError, type Tenant } from '../services/tenants.js';

/** One head read per sponsoring chain before a delete; a chain that does not answer counts as stale. */
const HEAD_TIMEOUT_MS = 3000;
const HISTORY_PAGE_SIZE = 50;

const errorSchema = z.object({ error: z.string(), message: z.string() }).passthrough();
const errors = { 400: errorSchema, 401: errorSchema, 404: errorSchema, 409: errorSchema, 412: errorSchema, 422: errorSchema, 428: errorSchema };
const slugParams = z.object({ slug: z.string().min(1).max(64) });
const statusSchema = z.enum(['active', 'suspended', 'deleted']);

const tenantSchema = z.object({
  id: z.string(),
  slug: z.string(),
  status: statusSchema,
  version: z.number().int(),
  walletOrigin: z.string(),
  rpId: z.string(),
  rpName: z.string(),
  expectedOrigins: z.array(z.string()),
  allowedDappOrigins: z.array(z.string()),
  corsOrigins: z.array(z.string()),
  openRegistration: z.boolean(),
  policy: z.record(z.unknown()),
  /** Stored and editable, and read by nothing yet (O-7). */
  branding: z.record(z.unknown()),
  createdAt: z.string(),
  updatedAt: z.string(),
  statusChangedAt: z.string().nullable(),
});

const tenantView = (tenant: Tenant): z.infer<typeof tenantSchema> => ({
  id: tenant.id,
  slug: tenant.slug,
  status: tenant.status,
  version: tenant.version,
  walletOrigin: tenant.walletOrigin,
  rpId: tenant.rpId,
  rpName: tenant.rpName,
  expectedOrigins: tenant.expectedOrigins,
  allowedDappOrigins: tenant.allowedDappOrigins,
  corsOrigins: tenant.corsOrigins,
  openRegistration: tenant.openRegistration,
  policy: tenant.policy as Record<string, unknown>,
  branding: tenant.branding as Record<string, unknown>,
  createdAt: tenant.createdAt.toISOString(),
  updatedAt: tenant.updatedAt.toISOString(),
  statusChangedAt: tenant.statusChangedAt?.toISOString() ?? null,
});

/** `"3"`, `W/"3"` or a bare `3`; null when absent or not a version. */
function ifMatchVersion(request: FastifyRequest): number | null | undefined {
  const header = request.headers['if-match'];
  if (header === undefined) return undefined;
  const match = /^(?:W\/)?"?(\d+)"?$/.exec(String(header).trim());
  return match ? Number(match[1]) : null;
}

function sendWriteError(reply: FastifyReply, error: unknown) {
  if (!(error instanceof TenantWriteError)) throw error;
  if (error.code === 'invalid-tenant') {
    // the same shape a create's schema validation produces
    const issues = (error.detail.issues as { path: (string | number)[]; message: string }[]).map((issue) => ({ path: `/${issue.path.join('/')}`, message: issue.message }));
    return reply.code(400).send({ error: 'validation', message: error.message, issues });
  }
  return reply.code(error.status).send({ error: error.code, message: error.message, ...error.detail });
}

/**
 * The operator tier's tenant registry (specs/OPERATOR-ADMIN-SPECS.md §7). Registered only when
 * OPERATOR_ADDRESSES is non-empty. Every route needs an operator session, refuses an Origin, and is
 * rate limited per session. Tenants are addressed by slug, which is what operators type;
 * responses always carry the id.
 */
export default async function operatorTenantRoutes(instance: FastifyInstance, opts: { db: Db; config: AppConfig; registry: ChainRegistry }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const admin = createTenantAdminService(opts.db);
  app.addHook('onRequest', app.requireOperator);

  const route = {
    config: {
      rateLimit: {
        max: opts.config.OPERATOR_RATE_LIMIT_PER_MINUTE,
        timeWindow: '1 minute',
        // requireOperator ran first (an instance hook), so the session is known here
        keyGenerator: (request: FastifyRequest) => `operator-session:${request.operator?.sessionId ?? 'none'}`,
      },
    },
  };
  const docs = { tags: ['operator'], security: [{ operatorSession: [] }] };

  app.get(
    '/v1/operator/tenants',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'List tenants, newest first; deleted tenants only when asked for',
        querystring: z.object({ status: statusSchema.optional() }),
        response: { 200: z.object({ tenants: z.array(tenantSchema.extend({ users: z.number().int() })) }), ...errors },
      },
    },
    async (request) => {
      const rows = await admin.list({ status: request.query.status });
      return { tenants: rows.map((row) => ({ ...tenantView(row), users: row.users })) };
    },
  );

  app.get(
    '/v1/operator/tenants/:slug',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'One tenant: fields, lifecycle, admin keys without key material, usage and ledger position',
        params: slugParams,
        response: {
          200: z.object({
            tenant: tenantSchema,
            adminKeys: z.array(z.object({ id: z.string(), label: z.string().nullable(), hashPrefix: z.string(), createdBy: z.string(), createdAt: z.string() })),
            users: z.number().int(),
            credentials: z.number().int(),
            lastUseropAt: z.string().nullable(),
            ledger: z.array(z.object({ chainId: z.number().int(), balanceWei: z.string(), deficitWei: z.string(), lastSyncedBlock: z.string().nullable() })),
          }),
          ...errors,
        },
      },
    },
    async (request, reply) => {
      try {
        const detail = await admin.detail(request.params.slug);
        reply.header('etag', `"${detail.tenant.version}"`);
        return {
          ...detail,
          tenant: tenantView(detail.tenant),
          adminKeys: detail.adminKeys.map((key) => ({ ...key, createdAt: key.createdAt.toISOString() })),
          lastUseropAt: detail.lastUseropAt ? new Date(detail.lastUseropAt).toISOString() : null,
        };
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.post(
    '/v1/operator/tenants',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Create an operator-managed tenant; generated admin keys are returned once',
        body: tenantCreateSchema,
        response: {
          201: z.object({ tenant: tenantSchema, adminKeys: z.array(z.object({ id: z.string(), label: z.string(), key: z.string() })) }),
          ...errors,
        },
      },
    },
    async (request, reply) => {
      try {
        const created = await admin.create(request.body, request.operator!);
        request.log.info({ slug: created.tenant.slug }, 'tenant created by operator');
        return reply.code(201).header('etag', `"${created.tenant.version}"`).send({ tenant: tenantView(created.tenant), adminKeys: created.adminKeys });
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.patch(
    '/v1/operator/tenants/:slug',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Update mutable fields; requires If-Match with the current version',
        params: slugParams,
        // the identity fields are accepted by the schema only so the handler can answer 422, not 400
        body: tenantPatchSchema.extend(Object.fromEntries(IMMUTABLE_TENANT_FIELDS.map((field) => [field, z.unknown().optional()]))),
        response: { 200: tenantSchema, ...errors },
      },
    },
    async (request, reply) => {
      const named = IMMUTABLE_TENANT_FIELDS.filter((field) => field in request.body);
      if (named.length > 0) {
        return reply.code(422).send({ error: 'immutable-field', message: `${named.join(', ')} cannot be changed; a tenant that needs one is a new tenant`, fields: named });
      }
      const version = ifMatchVersion(request);
      if (version === undefined) return reply.code(428).send({ error: 'precondition-required', message: 'If-Match with the tenant version is required' });
      if (version === null) return reply.code(412).send({ error: 'version-mismatch', message: 'If-Match must carry the tenant version, e.g. "3"' });
      const { slug: _slug, id: _id, walletOrigin: _origin, rpId: _rpId, ...patch } = request.body;
      try {
        const updated = await admin.update(request.params.slug, patch, version, request.operator!);
        return reply.header('etag', `"${updated.version}"`).send(tenantView(updated));
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.post(
    '/v1/operator/tenants/:slug/suspend',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'active → suspended: the tenant stops resolving on the next request',
        params: slugParams,
        body: z.object({ reason: z.string().min(1).max(500) }),
        response: { 200: tenantSchema, ...errors },
      },
    },
    async (request, reply) => {
      try {
        const tenant = await admin.suspend(request.params.slug, request.body.reason, request.operator!);
        request.log.warn({ slug: tenant.slug, reason: request.body.reason }, 'tenant suspended by operator');
        return reply.header('etag', `"${tenant.version}"`).send(tenantView(tenant));
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.post(
    '/v1/operator/tenants/:slug/resume',
    { ...route, schema: { ...docs, summary: 'suspended → active', params: slugParams, response: { 200: tenantSchema, ...errors } } },
    async (request, reply) => {
      try {
        const tenant = await admin.resume(request.params.slug, request.operator!);
        request.log.info({ slug: tenant.slug }, 'tenant resumed by operator');
        return reply.header('etag', `"${tenant.version}"`).send(tenantView(tenant));
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.delete(
    '/v1/operator/tenants/:slug',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'suspended → deleted: a tombstone; refused while funds or open reservations are attached',
        params: slugParams,
        response: { 204: z.null(), ...errors },
      },
    },
    async (request, reply) => {
      const sponsoring = opts.registry.all.filter((chain) => chain.paymaster);
      // read before the transaction, so no RPC call runs while the row lock is held
      const heads = new Map(
        await Promise.all(
          sponsoring.map(async (chain) => {
            const head = await Promise.race([
              chain.publicClient.getBlockNumber({ cacheTime: 0 }),
              new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), HEAD_TIMEOUT_MS).unref()),
            ]).catch(() => null);
            return [chain.chainId, head] as const;
          }),
        ),
      );
      try {
        await admin.remove(request.params.slug, request.operator!, {
          sponsoringChainIds: sponsoring.map((chain) => chain.chainId),
          heads,
          maxLagBlocks: opts.config.TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS,
        });
        request.log.warn({ slug: request.params.slug }, 'tenant deleted by operator');
        return reply.code(204).send(null);
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.post(
    '/v1/operator/tenants/:slug/admin-keys',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Issue a generated admin key; the plaintext is returned once',
        params: slugParams,
        body: z.object({ label: z.string().min(1).max(64) }),
        response: { 201: z.object({ id: z.string(), label: z.string(), key: z.string() }), ...errors },
      },
    },
    async (request, reply) => {
      try {
        return reply.code(201).send(await admin.issueAdminKey(request.params.slug, request.body.label, request.operator!));
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.delete(
    '/v1/operator/tenants/:slug/admin-keys/:keyId',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Revoke an admin key; refused for the last key of a tenant with closed registration',
        params: slugParams.extend({ keyId: z.string().uuid() }),
        response: { 204: z.null(), ...errors },
      },
    },
    async (request, reply) => {
      try {
        await admin.revokeAdminKey(request.params.slug, request.params.keyId, request.operator!);
        return reply.code(204).send(null);
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.get(
    '/v1/operator/tenants/:slug/history',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Every write to the tenant, newest first, 50 per page',
        params: slugParams,
        querystring: z.object({ before: z.string().uuid().optional() }),
        response: {
          200: z.object({
            entries: z.array(
              z.object({
                id: z.string(),
                action: z.string(),
                actor: z.string(),
                operatorSessionId: z.string().nullable(),
                before: z.record(z.unknown()).nullable(),
                after: z.record(z.unknown()).nullable(),
                detail: z.record(z.unknown()).nullable(),
                createdAt: z.string(),
              }),
            ),
            next: z.string().nullable(),
          }),
          ...errors,
        },
      },
    },
    async (request, reply) => {
      try {
        const page = await admin.history(request.params.slug, { before: request.query.before, limit: HISTORY_PAGE_SIZE });
        return {
          next: page.next,
          entries: page.entries.map((entry) => ({
            id: entry.id,
            action: entry.action,
            actor: entry.actor,
            operatorSessionId: entry.operatorSessionId,
            before: entry.before as Record<string, unknown> | null,
            after: entry.after as Record<string, unknown> | null,
            detail: entry.detail as Record<string, unknown> | null,
            createdAt: entry.createdAt.toISOString(),
          })),
        };
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );
}
