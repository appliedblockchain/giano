import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import { sha256hex } from '../services/tenants.js';

declare module 'fastify' {
  interface FastifyInstance {
    metrics: {
      useropRelayed: Counter<'status' | 'tenant'>;
      policyRejections: Counter<'rule' | 'tenant'>;
      ceremonyFailures: Counter<'kind' | 'tenant'>;
      useropLatency: Histogram<'tenant'>;
      /** ALERTABLE: if this ever fires, RP resolution is broken or someone is probing. */
      crossTenantRejections: Counter<'kind' | 'tenant'>;
    };
  }
}

/**
 * Prometheus metrics for the userop relay and ceremonies, exposed at GET /metrics.
 * Every metric carries a `tenant` label (the slug — human-readable, bounded
 * cardinality) so per-tenant billing/alerting/capacity dashboards are possible.
 * When `bearerToken` is set the endpoint requires it (D3.6 — per-tenant volumes are
 * not public data); unset keeps it open for dev/compose stacks.
 */
export default fp(
  async (app: FastifyInstance, opts: { bearerToken?: string }) => {
    const registry = new Registry();
    collectDefaultMetrics({ register: registry });

    const metrics = {
      useropRelayed: new Counter({
        name: 'giano_userop_relayed_total',
        help: 'User operations processed by the relay, by outcome and tenant',
        labelNames: ['status', 'tenant'] as const,
        registers: [registry],
      }),
      policyRejections: new Counter({
        name: 'giano_userop_policy_rejections_total',
        help: 'Policy rule rejections, by rule and tenant',
        labelNames: ['rule', 'tenant'] as const,
        registers: [registry],
      }),
      ceremonyFailures: new Counter({
        name: 'giano_ceremony_failures_total',
        help: 'WebAuthn ceremony verification failures, by kind and tenant',
        labelNames: ['kind', 'tenant'] as const,
        registers: [registry],
      }),
      useropLatency: new Histogram({
        name: 'giano_userop_relay_seconds',
        help: 'Latency of the userop relay endpoint',
        labelNames: ['tenant'] as const,
        buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5],
        registers: [registry],
      }),
      crossTenantRejections: new Counter({
        name: 'giano_cross_tenant_rejections_total',
        help: "Requests rejected for crossing a tenant boundary (kind: credential|challenge|session) — alert on any increase",
        labelNames: ['kind', 'tenant'] as const,
        registers: [registry],
      }),
    };
    app.decorate('metrics', metrics);

    app.get('/metrics', { schema: { hide: true } }, async (request, reply) => {
      if (opts.bearerToken) {
        const header = request.headers.authorization;
        const presented = header?.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : '';
        // compare sha256 digests so lengths always match for timingSafeEqual
        const ok = presented && timingSafeEqual(Buffer.from(sha256hex(presented)), Buffer.from(sha256hex(opts.bearerToken)));
        if (!ok) {
          return reply.code(401).send({ error: 'unauthorized', message: 'metrics bearer token required' });
        }
      }
      reply.header('content-type', registry.contentType);
      return registry.metrics();
    });
  },
  { name: 'metrics' },
);
