import { createPublicClient, formatEther, http, type PublicClient } from 'viem';
import { pino } from 'pino';
import { ConfigError, loadConfig, type BundlerConfig, type ChainType } from './config.js';
import { createEstimator } from './estimator.js';
import { createLookup } from './lookup.js';
import { createMetrics } from './metrics.js';
import { GAS_PRICE_ORACLE } from './pvg.js';
import { createRpcServer } from './rpc.js';
import { createSubmitter } from './submitter.js';

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

const client = createPublicClient({ transport: http(config.rpcUrl, { retryCount: 2, timeout: 30_000 }) }) as PublicClient;

/**
 * What the chain must be before anything is served: reachable, with the EntryPoint deployed.
 * Both are waited for rather than refused — the node may be starting alongside us, and a fresh
 * devnet gets its contracts after `up` — so until then nothing listens and the healthcheck fails.
 */
async function connect(): Promise<{ chainId: number; chainType: ChainType }> {
  for (let attempt = 1; ; attempt++) {
    try {
      const chainId = await client.getChainId();
      const code = await client.getCode({ address: config.entryPoint });
      if (code && code !== '0x') {
        let chainType = config.chainType;
        if (chainType === 'auto') {
          const oracle = await client.getCode({ address: GAS_PRICE_ORACLE });
          chainType = oracle && oracle !== '0x' ? 'op-stack' : 'default';
        }
        return { chainId, chainType };
      }
      if (attempt % 10 === 1) log.error({ chainId, entryPoint: config.entryPoint }, 'no EntryPoint is deployed at the configured address yet; waiting');
    } catch (error) {
      if (attempt % 10 === 1) log.warn({ attempt, err: (error as Error).message }, 'waiting for the chain RPC');
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
}

const metrics = createMetrics();
const { chainId, chainType } = await connect();

const submitter = createSubmitter({
  client,
  chainId,
  entryPoint: config.entryPoint,
  executors: config.executors,
  resubmitTimeoutMs: config.resubmitTimeoutMs,
  maxReplacements: config.maxReplacements,
  pollIntervalMs: config.pollIntervalMs,
  log,
  metrics,
});
const estimator = createEstimator({ client, entryPoint: config.entryPoint, chainId, chainType, executor: config.executors[0].address });
const lookup = createLookup({ client, chainId, entryPoint: config.entryPoint, maxBlockRange: config.maxBlockRange, submitter });

for (const executor of config.executors) {
  const balance = await client.getBalance({ address: executor.address });
  metrics.executorBalance.set({ executor: executor.address }, Number(balance));
  if (balance === 0n) log.warn({ executor: executor.address }, 'executor has no balance: every submission will fail until it is funded');
  else log.info({ executor: executor.address, balance: formatEther(balance) }, 'executor');
}
setInterval(() => void submitter.refreshBalances(), 60_000).unref();

const server = createRpcServer({ chainId, entryPoint: config.entryPoint, estimator, submitter, lookup, metrics, log }, () => true);
server.listen(config.port, config.host, () => {
  log.info({ chainId, chainType, entryPoint: config.entryPoint, port: config.port, executors: submitter.executors.length }, 'giano-bundler listening');
});

// The image's runtime has no init process: Node runs as PID 1, which has no default action for
// SIGTERM, so without this handler ECS waits out the stop timeout and sends SIGKILL. In-flight
// transactions are not lost by exiting — they are on the chain's mempool, and receipts are found
// from the chain's logs after a restart.
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, () => {
    log.info({ signal }, 'shutting down');
    submitter.stop();
    server.close();
    setTimeout(() => process.exit(0), 500).unref();
  });
}
