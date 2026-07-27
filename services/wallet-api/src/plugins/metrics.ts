import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

declare module 'fastify' {
  interface FastifyInstance {
    metrics: {
      useropRelayed: Counter<'status'>;
      policyRejections: Counter<'rule'>;
      ceremonyFailures: Counter<'kind'>;
      useropLatency: Histogram<string>;
    };
  }
}

/**
 * Prometheus metrics for the userop relay and ceremonies, exposed at GET /metrics.
 * Structured pino logs cover the rest; this is the numeric signal for dashboards/alerts.
 */
export default fp(
  async (app: FastifyInstance) => {
    const registry = new Registry();
    collectDefaultMetrics({ register: registry });

    const metrics = {
      useropRelayed: new Counter({
        name: 'giano_userop_relayed_total',
        help: 'User operations processed by the relay, by outcome',
        labelNames: ['status'] as const,
        registers: [registry],
      }),
      policyRejections: new Counter({
        name: 'giano_userop_policy_rejections_total',
        help: 'Policy rule rejections, by rule',
        labelNames: ['rule'] as const,
        registers: [registry],
      }),
      ceremonyFailures: new Counter({
        name: 'giano_ceremony_failures_total',
        help: 'WebAuthn ceremony verification failures, by kind',
        labelNames: ['kind'] as const,
        registers: [registry],
      }),
      useropLatency: new Histogram({
        name: 'giano_userop_relay_seconds',
        help: 'Latency of the userop relay endpoint',
        buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5],
        registers: [registry],
      }),
    };
    app.decorate('metrics', metrics);

    app.get('/metrics', { schema: { hide: true } }, async (_request, reply) => {
      reply.header('content-type', registry.contentType);
      return registry.metrics();
    });
  },
  { name: 'metrics' },
);
