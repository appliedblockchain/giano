import { createPublicClient, formatEther, http, type PublicClient } from 'viem';
import type { PrivateKeyAccount } from 'viem/accounts';
import type { Logger } from 'pino';
import type { ChainConfig, ChainType } from './config.js';
import { createEstimator, type Estimator } from './estimator.js';
import { createLookup, type Lookup } from './lookup.js';
import type { Metrics } from './metrics.js';
import { GAS_PRICE_ORACLE } from './pvg.js';
import { createSubmitter, type Submitter } from './submitter.js';

/**
 * The chain registry: one entry per served chain, each with its own client, executor lanes,
 * estimator and lookup — nothing chain-bound is shared between chains, the same rule wallet-api's
 * registry keeps (MC-50). A chain becomes ready once its RPC answers with the configured chain id
 * and its EntryPoint has code; until then it is retried in the background and its requests are
 * refused as unavailable, while every other chain keeps serving (MC-54).
 */

export type ChainServices = {
  chainId: number;
  chainType: ChainType;
  entryPoint: ChainConfig['entryPoint'];
  client: PublicClient;
  estimator: Estimator;
  submitter: Submitter;
  lookup: Lookup;
};

export type ChainEntry = {
  config: ChainConfig;
  status: 'connecting' | 'ready';
  /** Present once ready. */
  services?: ChainServices;
  /** Why it is not ready yet, for /health. */
  waitingFor?: string;
};

export type ChainRegistry = ReturnType<typeof createChainRegistry>;

export function createChainRegistry(options: {
  chains: ChainConfig[];
  executors: PrivateKeyAccount[];
  resubmitTimeoutMs: number;
  maxReplacements: number;
  pollIntervalMs: number;
  /** Delay between connection attempts for a chain that is not ready. */
  retryMs?: number;
  log: Logger;
  metrics: Metrics;
}) {
  const { executors, log, metrics } = options;
  const retryMs = options.retryMs ?? 3000;
  const entries = new Map<number, ChainEntry>(options.chains.map((config) => [config.chainId, { config, status: 'connecting' }]));
  const timers = new Set<NodeJS.Timeout>();
  let stopped = false;

  const connect = async (entry: ChainEntry, attempt: number): Promise<void> => {
    const { config } = entry;
    const chainLog = log.child({ chainId: config.chainId });
    const client = createPublicClient({ transport: http(config.rpcUrl, { retryCount: 2, timeout: 30_000 }) }) as PublicClient;
    try {
      const reported = await client.getChainId();
      if (reported !== config.chainId) {
        // Not transient, but not this process's to fix by exiting either: the other chains are fine.
        entry.waitingFor = `the RPC reports chain ${reported}`;
        if (attempt % 10 === 1) chainLog.error({ reported }, 'the RPC serves a different chain than GIANO_CHAINS declares; waiting');
      } else {
        const code = await client.getCode({ address: config.entryPoint });
        if (code && code !== '0x') {
          let chainType = config.chainType;
          if (chainType === 'auto') {
            const oracle = await client.getCode({ address: GAS_PRICE_ORACLE });
            chainType = oracle && oracle !== '0x' ? 'op-stack' : 'default';
          }
          entry.services = await build(config, client, chainType, chainLog);
          entry.status = 'ready';
          entry.waitingFor = undefined;
          metrics.chainReady.set({ chain: String(config.chainId) }, 1);
          chainLog.info({ name: config.name, chainType, entryPoint: config.entryPoint }, 'chain ready');
          return;
        }
        // A fresh devnet gets its contracts after `up`, so this is waited for rather than fatal.
        entry.waitingFor = `no EntryPoint at ${config.entryPoint}`;
        if (attempt % 10 === 1) chainLog.error({ entryPoint: config.entryPoint }, 'no EntryPoint is deployed at the configured address yet; waiting');
      }
    } catch (error) {
      entry.waitingFor = 'the RPC is unreachable';
      if (attempt % 10 === 1) chainLog.warn({ attempt, err: (error as Error).message }, 'waiting for the chain RPC');
    }
    if (stopped) return;
    const timer = setTimeout(() => {
      timers.delete(timer);
      void connect(entry, attempt + 1);
    }, retryMs);
    timers.add(timer);
  };

  const build = async (config: ChainConfig, client: PublicClient, chainType: ChainType, chainLog: Logger): Promise<ChainServices> => {
    const submitter = createSubmitter({
      client,
      chainId: config.chainId,
      entryPoint: config.entryPoint,
      executors,
      resubmitTimeoutMs: options.resubmitTimeoutMs,
      maxReplacements: options.maxReplacements,
      pollIntervalMs: options.pollIntervalMs,
      log: chainLog,
      metrics,
    });
    for (const executor of executors) {
      const balance = await client.getBalance({ address: executor.address });
      metrics.executorBalance.set({ chain: String(config.chainId), executor: executor.address }, Number(balance));
      if (balance === 0n) chainLog.warn({ executor: executor.address }, 'executor has no balance on this chain: every submission will fail until it is funded');
      else chainLog.info({ executor: executor.address, balance: formatEther(balance) }, 'executor');
    }
    return {
      chainId: config.chainId,
      chainType,
      entryPoint: config.entryPoint,
      client,
      submitter,
      estimator: createEstimator({ client, entryPoint: config.entryPoint, chainId: config.chainId, chainType, executor: executors[0].address }),
      lookup: createLookup({ client, chainId: config.chainId, entryPoint: config.entryPoint, maxBlockRange: config.maxBlockRange, submitter }),
    };
  };

  const balances = setInterval(() => {
    for (const entry of entries.values()) void entry.services?.submitter.refreshBalances();
  }, 60_000);
  balances.unref();

  return {
    /** Starts connecting every chain; resolves at once, readiness follows per chain. */
    start() {
      for (const entry of entries.values()) {
        metrics.chainReady.set({ chain: String(entry.config.chainId) }, 0);
        void connect(entry, 1);
      }
    },
    get: (chainId: number) => entries.get(chainId),
    all: () => [...entries.values()],
    servedChainIds: () => [...entries.keys()],
    stop() {
      stopped = true;
      clearInterval(balances);
      for (const timer of timers) clearTimeout(timer);
      for (const entry of entries.values()) entry.services?.submitter.stop();
    },
  };
}
