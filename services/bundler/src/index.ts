import { pino } from 'pino';
import { ConfigError, loadConfig, type BundlerConfig } from './config.js';
import { createMetrics } from './metrics.js';
import { createChainRegistry } from './registry.js';
import { createRpcServer } from './rpc.js';

let config: BundlerConfig;
try {
  config = loadConfig();
} catch (error) {
  if (!(error instanceof ConfigError)) throw error;
  console.error(error.message);
  process.exit(1);
}

const log = pino({ level: config.logLevel, base: { service: 'giano-bundler' } });
for (const warning of config.warnings) log.warn(warning);

const metrics = createMetrics();
const registry = createChainRegistry({
  chains: config.chains,
  executors: config.executors,
  resubmitTimeoutMs: config.resubmitTimeoutMs,
  maxReplacements: config.maxReplacements,
  pollIntervalMs: config.pollIntervalMs,
  log,
  metrics,
});
registry.start();

const server = createRpcServer({ registry, metrics, log });
server.listen(config.port, config.host, () => {
  log.info(
    { port: config.port, chains: config.chains.map((chain) => chain.chainId), executors: config.executors.length },
    'giano-bundler listening',
  );
});

// The image's runtime has no init process: Node runs as PID 1, which has no default action for
// SIGTERM, so without this handler ECS waits out the stop timeout and sends SIGKILL. In-flight
// transactions are not lost by exiting — they are on the chain's mempool, and receipts are found
// from the chain's logs after a restart.
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, () => {
    log.info({ signal }, 'shutting down');
    registry.stop();
    server.close();
    setTimeout(() => process.exit(0), 500).unref();
  });
}
