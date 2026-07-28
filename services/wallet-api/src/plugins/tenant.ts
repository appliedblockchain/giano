import type { FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type { Tenant, TenantService } from '../services/tenants.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Tenant resolved for this request (Origin header, session, or admin key). */
    tenant: Tenant | null;
  }
  interface FastifyInstance {
    tenants: TenantService;
    requireTenant: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireTenantByHost: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

/**
 * Per-request tenant resolution (docs/MULTI-TENANCY-GAPS.md §5.2). The Origin header is
 * authoritative for ceremony routes because WebAuthn independently verifies the ceremony
 * ran on that origin (clientDataJSON.origin must match the resolved tenant's
 * expected_origins); the Host header is authoritative for /.well-known/webauthn.
 *
 * The onRequest hook only ever *identifies* — failing closed is the job of the route
 * guards, because /healthz, /metrics, /docs and the public receipt endpoint are
 * deliberately tenant-free.
 */
export default fp(
  async (app, opts: { tenants: TenantService }) => {
    app.decorate('tenants', opts.tenants);
    app.decorateRequest('tenant', null);

    app.addHook('onRequest', async (request) => {
      const origin = request.headers.origin;
      if (typeof origin !== 'string' || origin === 'null' || !origin) return;
      const tenant = await opts.tenants.getByOrigin(origin);
      if (tenant) {
        request.tenant = tenant;
        request.log = request.log.child({ tenant: tenant.slug });
      }
    });

    /** Fail closed: an unknown Origin never falls back to any default tenant. */
    app.decorate('requireTenant', async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.tenant) {
        return reply.code(403).send({ error: 'unknown-tenant', message: 'Origin header missing or not a registered tenant origin' });
      }
    });

    /** Host-based resolution for the ROR well-known document (no Origin on same-origin GETs). */
    app.decorate('requireTenantByHost', async (request: FastifyRequest, reply: FastifyReply) => {
      const host = request.headers.host;
      const tenant = host ? await opts.tenants.getByHost(host) : null;
      if (!tenant) {
        // a probe on the API's raw host learns nothing
        return reply.code(404).send({ error: 'not-found', message: 'not found' });
      }
      request.tenant = tenant;
      request.log = request.log.child({ tenant: tenant.slug });
    });
  },
  { name: 'tenant' },
);
