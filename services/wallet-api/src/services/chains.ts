import { createPublicClient, http, type PublicClient } from 'viem';
import type { AppConfig, ResolvedChain } from '../config.js';
import { createBundlerService, type BundlerService } from './bundler.js';
import { createPaymasterReader, type PaymasterReader } from './paymaster-contract.js';
import type { LedgerService } from './sponsorship-ledger.js';
import { createSponsorshipService, type SponsorshipService } from './sponsorship-service.js';
import type { SponsorshipSigner } from './sponsorship-signer.js';
import type { Db } from '../db/index.js';

/**
 * The chain registry: the ONLY way the backend reaches a chain (MC-96). One entry per
 * configured chain, each holding its own read client, bundler, paymaster reader and
 * sponsorship service — nothing chain-bound is ever shared between chains (MC-50), so no
 * operation for one chain can be submitted through another chain's endpoint (MC-58).
 *
 * One process, per-chain isolation inside it (Q3): this registry is the seam — if
 * per-chain process isolation is ever wanted, it is the only thing that changes shape.
 */

export type ChainServices = {
  descriptor: ResolvedChain;
  chainId: number;
  publicClient: PublicClient;
  bundler: BundlerService;
  entryPoint: `0x${string}`;
  factory: `0x${string}`;
  /** Present when sponsorship is enabled for this chain. */
  paymaster?: PaymasterReader;
  sponsorship?: SponsorshipService;
  /**
   * 'unavailable' = the endpoint could not be reached — a transient condition, retried in
   * the background, distinct from a structural misconfiguration (which refuses boot, MC-92).
   */
  status: 'ready' | 'unavailable';
};

export class UnknownChainError extends Error {
  constructor(
    public readonly chainId: number,
    public readonly servedChainIds: number[],
  ) {
    super(`this deployment does not serve chain ${chainId} (served: ${servedChainIds.join(', ')})`);
    this.name = 'UnknownChainError';
  }
}

export type ChainRegistry = {
  get: (chainId: number) => ChainServices;
  tryGet: (chainId: number) => ChainServices | undefined;
  /**
   * The only chain, when exactly one is configured. Throws otherwise — it is the
   * single-chain affordance behind MC-53, NOT a default chain: nothing resolves to it when
   * several chains are served.
   */
  readonly sole: ChainServices;
  readonly all: readonly ChainServices[];
  readonly size: number;
  servedChainIds: () => number[];
  /**
   * Any ready chain, for work that is chain-INDEPENDENT by construction — deriving a wallet
   * address from the factory, which MC-16/MC-22 guarantee (and boot verification checked)
   * answers identically on every served chain.
   */
  anyReady: () => ChainServices;
};

export type BuildChainRegistryOptions = {
  config: AppConfig;
  db: Db;
  ledger: LedgerService;
  fetchImpl?: typeof fetch;
  /** Built once and shared: authorisations are separated per chain and per paymaster (MC-72). */
  signer?: SponsorshipSigner;
  /** Test override, applied to every sponsoring chain. */
  paymasterReader?: PaymasterReader;
  onDecision?: (chainId: number) => Parameters<typeof createSponsorshipService>[0]['onDecision'];
};

export function buildChainRegistry(options: BuildChainRegistryOptions): ChainRegistry {
  const { config, db, ledger, fetchImpl, signer, paymasterReader, onDecision } = options;

  const entries = new Map<number, ChainServices>();

  for (const descriptor of config.CHAINS) {
    const publicClient = createPublicClient({ transport: http(descriptor.rpcUrl) });
    const bundler = createBundlerService(descriptor.bundlerUrl, descriptor.entryPoint, fetchImpl);

    let paymaster: PaymasterReader | undefined;
    let sponsorship: SponsorshipService | undefined;
    // Sponsorship is available independently per chain (MC-65): enabled deployment-wide by
    // the master switch, and on each chain by that chain resolving a paymaster.
    if (config.SPONSORSHIP_ENABLED && descriptor.sponsorshipPaymaster && signer) {
      paymaster = paymasterReader ?? createPaymasterReader({ client: publicClient, address: descriptor.sponsorshipPaymaster });
      sponsorship = createSponsorshipService({
        db,
        chainId: descriptor.chainId,
        paymaster,
        ledger,
        signer,
        entryPoint: descriptor.entryPoint,
        validitySeconds: config.SPONSORSHIP_VALIDITY_SECONDS,
        reservationTtlSeconds: config.SPONSORSHIP_RESERVATION_TTL_SECONDS,
        walletManagementCapWei: config.SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI,
        isEmergencyStopped: () => config.SPONSORSHIP_EMERGENCY_STOP,
        onDecision: onDecision?.(descriptor.chainId),
      });
    }

    entries.set(descriptor.chainId, {
      descriptor,
      chainId: descriptor.chainId,
      publicClient,
      bundler,
      entryPoint: descriptor.entryPoint,
      factory: descriptor.factory,
      paymaster,
      sponsorship,
      status: 'ready',
    });
  }

  const all = [...entries.values()];
  const servedChainIds = () => all.map((entry) => entry.chainId);

  return {
    get(chainId) {
      const entry = entries.get(chainId);
      if (!entry) throw new UnknownChainError(chainId, servedChainIds());
      return entry;
    },
    tryGet: (chainId) => entries.get(chainId),
    get sole() {
      if (all.length !== 1) {
        throw new Error(`registry.sole is a single-chain affordance — ${all.length} chains are configured (MC-53: never guess)`);
      }
      return all[0];
    },
    get all() {
      return all;
    },
    get size() {
      return all.length;
    },
    servedChainIds,
    anyReady() {
      const ready = all.find((entry) => entry.status === 'ready');
      if (!ready) throw new Error('no chain is currently available');
      return ready;
    },
  };
}
