import { timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type { OperatorContext, OperatorSessionService } from '../services/operator-sessions.js';
import type { SessionContext, SessionService } from '../services/sessions.js';
import type { Tenant, TenantService } from '../services/tenants.js';
import { sha256hex } from '../services/tenants.js';

declare module 'fastify' {
  interface FastifyRequest {
    session: SessionContext | null;
    /** Tenant whose admin key authorized this request (set by requireAdmin). */
    adminTenant: Tenant | null;
    /** The operator whose session authorized this request (set by requireOperator). */
    operator: OperatorContext | null;
  }
  interface FastifyInstance {
    requireSession: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireAdmin: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    resolveAdminTenant: (request: FastifyRequest) => Promise<Tenant | null>;
    refuseOperatorOrigin: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireOperator: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

/** One body for every operator authentication failure, whatever the cause (no oracle). */
export const OPERATOR_UNAUTHORIZED = { error: 'unauthorized', message: 'operator session required' } as const;

export function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim() || null;
}

export default fp(
  async (app, opts: { sessions: SessionService; tenants: TenantService; operatorSessions?: OperatorSessionService }) => {
    app.decorateRequest('session', null);
    app.decorateRequest('adminTenant', null);
    app.decorateRequest('operator', null);

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
      // No Origin (server-to-server, same-origin GET): the session IS the tenant authority —
      // but only while that tenant is active. A session minted before a suspension must not keep
      // working on calls that carry no Origin; same generic body as an invalid token.
      if (!request.tenant) {
        const tenant = await opts.tenants.getActiveById(session.tenantId);
        if (!tenant) {
          return reply.code(401).send({ error: 'unauthorized', message: 'invalid or expired session' });
        }
        request.tenant = tenant;
        request.log = request.log.child({ tenant: tenant.slug });
      }
      request.session = session;
    });

    /**
     * Operator routes refuse any request carrying an Origin (specs/OPERATOR-ADMIN-SPECS.md §4.5):
     * no browser page on any origin can call them cross-origin, whatever CORS answers. The
     * console reaches them through its own proxy, which strips the header. A cheap extra layer,
     * not the access control — operator tokens are never attached by the browser on its own.
     */
    app.decorate('refuseOperatorOrigin', async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers.origin !== undefined) {
        return reply.code(403).send({ error: 'operator-origin-refused', message: 'operator routes cannot be called from a browser page' });
      }
    });

    /**
     * Operator session → operator (§4.4). Never shares a lookup with requireAdmin: a tenant admin
     * key is not a session hash, and a session token is not in tenant_admin_keys.
     */
    app.decorate('requireOperator', async (request: FastifyRequest, reply: FastifyReply) => {
      await app.refuseOperatorOrigin(request, reply);
      if (reply.sent) return reply;
      const token = bearerToken(request);
      const operator = token && opts.operatorSessions ? await opts.operatorSessions.resolve(token) : null;
      if (!operator) {
        app.metrics.operatorAuthFailures.inc({ reason: token ? 'invalid-session' : 'missing-token' });
        return reply.code(401).send(OPERATOR_UNAUTHORIZED);
      }
      request.operator = operator;
      request.log = request.log.child({ operator: operator.id });
    });
  },
  { name: 'auth', dependencies: ['tenant', 'metrics'] },
);
