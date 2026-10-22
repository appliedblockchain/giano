import { Counter, Gauge, Registry, collectDefaultMetrics } from 'prom-client';

export type Metrics = ReturnType<typeof createMetrics>;

export function createMetrics() {
  const registry = new Registry();
  collectDefaultMetrics({ register: registry, prefix: 'giano_bundler_' });
  return {
    registry,
    rpcRequests: new Counter({
      name: 'giano_bundler_rpc_requests_total',
      help: 'JSON-RPC requests by method and outcome (ok, or the JSON-RPC error code)',
      labelNames: ['method', 'outcome'] as const,
      registers: [registry],
    }),
    userOperations: new Counter({
      name: 'giano_bundler_user_operations_total',
      help: 'User operations by lifecycle outcome: submitted, included, reverted, dropped, rejected',
      labelNames: ['outcome'] as const,
      registers: [registry],
    }),
    executorBalance: new Gauge({
      name: 'giano_bundler_executor_balance_wei',
      help: 'Native balance of each executor account, in wei',
      labelNames: ['executor'] as const,
      registers: [registry],
    }),
  };
}
