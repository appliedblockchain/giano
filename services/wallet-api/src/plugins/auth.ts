import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type { SessionContext, SessionService } from '../services/sessions.js';
import type { Tenant, TenantService } from '../services/tenants.js';
import { sha256hex } from '../services/tenants.js';

declare module 'fastify' {
  interface FastifyRequest {
    session: SessionContext | null;
    /** Tenant whose admin key authorized this request (set by requireAdmin). */
    adminTenant: Tenant | null;
  }
  interface FastifyInstance {
    requireSession: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireAdmin: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    resolveAdminTenant: (request: FastifyRequest) => Promise<Tenant | null>;
  }
}

function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim() || null;
}

export default fp(
  async (app, opts: { sessions: SessionService; tenants: TenantService }) => {
    app.decorateRequest('session', null);
    app.decorateRequest('adminTenant', null);

    /**
     * Admin key → tenant (G2.1/G2.4): sha256 the presented key and look it up by hash —
     * O(1) on a unique index, no length leak, no O(keys) scan. The timingSafeEqual over
     * the two equal-length hex digests is a belt-and-braces constant-time recheck.
     */
    app.decorate('resolveAdminTenant', async (request: FastifyRequest): Promise<Tenant | null> => {
      const token = bearerToken(request);
      if (!token) return null;
      const hash = sha256hex(token);
      const row = await opts.tenants.getByAdminKeyHash(hash);
      if (!row) return null;
      if (!timingSafeEqual(Buffer.from(hash), Buffer.from(row.keyHash))) return null;
      return row.tenant;
    });

    app.decorate('requireAdmin', async (request: FastifyRequest, reply: FastifyReply) => {
      const tenant = await app.resolveAdminTenant(request);
      if (!tenant) {
        return reply.code(401).send({ error: 'unauthorized', message: 'admin API key required' });
      }
      request.adminTenant = tenant;
    });

    app.decorate('requireSession', async (request: FastifyRequest, reply: FastifyReply) => {
      const token = bearerToken(request);
      if (!token) {
        return reply.code(401).send({ error: 'unauthorized', message: 'bearer session token required' });
      }
      const session = await opts.sessions.resolve(token);
      if (!session) {
        return reply.code(401).send({ error: 'unauthorized', message: 'invalid or expired session' });
      }
      // G2.3: a session is scoped to its tenant. When the request carries a resolvable
      // Origin, the two must agree — same generic body as an invalid token (no oracle).
      if (request.tenant && request.tenant.id !== session.tenantId) {
        request.log.warn({ alert: 'cross-tenant-session', sessionTenant: session.tenantId }, 'session token used on a foreign tenant origin');
        app.metrics.crossTenantRejections.inc({ tenant: request.tenant.slug, kind: 'session' });
        return reply.code(401).send({ error: 'unauthorized', message: 'invalid or expired session' });
      }
      // No Origin (server-to-server, same-origin GET): the session IS the tenant authority.
      if (!request.tenant) {
        request.tenant = await opts.tenants.getById(session.tenantId);
        if (request.tenant) request.log = request.log.child({ tenant: request.tenant.slug });
      }
      request.session = session;
    });
  },
  { name: 'auth', dependencies: ['tenant', 'metrics'] },
);
