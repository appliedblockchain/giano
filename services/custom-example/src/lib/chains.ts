import { createGianoWalletProvider, type GianoWalletProvider } from '@appliedblockchain/giano-connector';
import { createPublicClient, defineChain, http, type Chain, type PublicClient } from 'viem';
import type { ChainConfig } from '../config';

/**
 * One provider PER CHAIN, all over the same wallet origin (design.md D3). A provider is bound to one
 * chain for its life (MC-01), so addressing another chain means another provider — never a switch.
 * Selecting a chain in the UI selects a provider here.
 *
 * Providers are built lazily so the demo never opens a session it was not asked for, and so provider
 * OPTIONS (walletApiPath, storage, sdkVersion) can be changed per chain before the first use — the
 * next provider constructed for that chain uses them.
 */
export type ProviderOptions = {
  walletApiPath: string;
  storage: 'localStorage' | 'memory';
  sdkVersion?: string;
};

export const DEFAULT_PROVIDER_OPTIONS: ProviderOptions = { walletApiPath: '/api', storage: 'localStorage' };

export type ChainEntry = {
  config: ChainConfig;
  chain: Chain;
  /** True for a chain the user typed in, not one from runtime configuration. */
  adHoc: boolean;
  publicClient: PublicClient;
};

/** In-memory Storage look-alike for the `storage` option: disables session resume on purpose. */
function memoryStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
  const map = new Map<string, string>();
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => void map.set(key, value),
    removeItem: (key) => void map.delete(key),
  };
}

export function toViemChain(config: ChainConfig): Chain {
  const rpc = config.rpcUrl.startsWith('/') ? `${window.location.origin}${config.rpcUrl}` : config.rpcUrl;
  return defineChain({
    id: config.chainId,
    name: config.name,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
    blockExplorers: config.explorerUrl ? { default: { name: 'explorer', url: config.explorerUrl } } : undefined,
  });
}

export class ChainRegistry {
  private readonly entries = new Map<number, ChainEntry>();
  private readonly providers = new Map<number, GianoWalletProvider>();
  private readonly options = new Map<number, ProviderOptions>();
  private readonly listeners = new Set<(chainId: number, provider: GianoWalletProvider) => void>();

  constructor(
    public readonly walletUrl: string,
    configured: ChainConfig[],
  ) {
    for (const config of configured) this.register(config, false);
  }

  get walletOrigin(): string {
    return new URL(this.walletUrl).origin;
  }

  /** Every chain the demo can address, configured first, ad-hoc after. */
  list(): ChainEntry[] {
    return [...this.entries.values()];
  }

  get(chainId: number): ChainEntry | undefined {
    return this.entries.get(chainId);
  }

  require(chainId: number): ChainEntry {
    const entry = this.entries.get(chainId);
    if (!entry) throw new Error(`chain ${chainId} is not registered in the demo`);
    return entry;
  }

  /** The free-form path: a chain the wallet may or may not serve, for provoking 4902/4901. */
  addAdHocChain(chainId: number, rpcUrl: string, name = `chain ${chainId}`): ChainEntry {
    return this.register({ chainId, name, rpcUrl }, true);
  }

  private register(config: ChainConfig, adHoc: boolean): ChainEntry {
    const chain = toViemChain(config);
    const entry: ChainEntry = { config, chain, adHoc, publicClient: createPublicClient({ chain, transport: http(chain.rpcUrls.default.http[0]) }) };
    this.entries.set(config.chainId, entry);
    return entry;
  }

  optionsFor(chainId: number): ProviderOptions {
    return this.options.get(chainId) ?? DEFAULT_PROVIDER_OPTIONS;
  }

  /** Applies to the NEXT provider built for that chain; an existing one is dropped so the change takes effect. */
  setOptions(chainId: number, options: ProviderOptions): void {
    this.options.set(chainId, options);
    const existing = this.providers.get(chainId);
    if (existing) {
      existing.disconnect();
      this.providers.delete(chainId);
    }
  }

  hasProvider(chainId: number): boolean {
    return this.providers.has(chainId);
  }

  /** The thin two-origin provider for this chain, built on first use. */
  providerFor(chainId: number): GianoWalletProvider {
    let provider = this.providers.get(chainId);
    if (!provider) {
      const entry = this.require(chainId);
      const options = this.optionsFor(chainId);
      provider = createGianoWalletProvider({
        walletUrl: this.walletUrl,
        chain: entry.chain,
        transport: http(entry.chain.rpcUrls.default.http[0]),
        walletApiPath: options.walletApiPath,
        storage: options.storage === 'memory' ? memoryStorage() : undefined,
        ...(options.sdkVersion ? { sdkVersion: options.sdkVersion } : {}),
      });
      this.providers.set(chainId, provider);
      for (const listener of this.listeners) listener(chainId, provider);
    }
    return provider;
  }

  /** A throwaway provider against ANOTHER wallet origin — the disallowed-origin control (origin-not-allowed). */
  foreignProvider(walletUrl: string, chainId: number): GianoWalletProvider {
    const entry = this.require(chainId);
    return createGianoWalletProvider({ walletUrl, chain: entry.chain, transport: http(entry.chain.rpcUrls.default.http[0]), storage: memoryStorage() });
  }

  /** Called whenever a provider is constructed, so the store can subscribe to its events. */
  onProvider(listener: (chainId: number, provider: GianoWalletProvider) => void): () => void {
    this.listeners.add(listener);
    for (const [chainId, provider] of this.providers) listener(chainId, provider);
    return () => void this.listeners.delete(listener);
  }
}
