import { Counter, collectDefaultMetrics, Gauge, Registry } from "prom-client";

export type Metrics = ReturnType<typeof createMetrics>;

export function createMetrics() {
	const registry = new Registry();
	collectDefaultMetrics({ register: registry, prefix: "giano_bundler_" });
	return {
		registry,
		rpcRequests: new Counter({
			name: "giano_bundler_rpc_requests_total",
			help: "JSON-RPC requests by method and outcome (ok, or the JSON-RPC error code)",
			labelNames: ["chain", "method", "outcome"] as const,
			registers: [registry],
		}),
		userOperations: new Counter({
			name: "giano_bundler_user_operations_total",
			help: "User operations by lifecycle outcome: submitted, included, reverted, dropped, rejected",
			labelNames: ["chain", "outcome"] as const,
			registers: [registry],
		}),
		executorBalance: new Gauge({
			name: "giano_bundler_executor_balance_wei",
			help: "Native balance of each executor account on each chain, in wei",
			labelNames: ["chain", "executor"] as const,
			registers: [registry],
		}),
		chainReady: new Gauge({
			name: "giano_bundler_chain_ready",
			help: "1 when the chain is connected and serving, 0 while it is being retried",
			labelNames: ["chain"] as const,
			registers: [registry],
		}),
	};
}
