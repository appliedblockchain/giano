import { describeTransaction as describeWithLibrary, type Mapping, type TokenInfo, type TransactionDescription } from '@appliedblockchain/giano-tx-describe';
import { erc20Abi, type PublicClient } from 'viem';
import type { WalletChainConfig } from './config';
import type { TransactionRequest } from './runtimes';

/**
 * The kit's half of transaction descriptions: everything the library refuses to do itself.
 *
 * The library is pure (R1 of the ticket) — it neither fetches the tenant's mappings nor reads a
 * token's decimals. The runtime does both here, bounded and cached, and hands the results in. It
 * lives in the kit rather than in wallet-web so that a bring-your-own origin gets the same
 * description from the same call (WK-30), and so that neither UI ever talks to wallet-api about
 * mappings directly.
 *
 * Nothing on this path may reject. A mapping fetch that fails leaves the built-ins; a token read
 * that fails leaves an unscaled amount; both are reported as warnings on the description.
 */

export type CreateTransactionDescriberOptions = {
  chainId: number;
  /** Base URL of the wallet-api ('/api' when proxied same-origin). */
  walletApiUrl: string;
  publicClient: Pick<PublicClient, 'readContract'>;
  nativeCurrency: WalletChainConfig['nativeCurrency'];
  /** Defaults to the global fetch, resolved at call time so a test can stub it. */
  fetch?: typeof fetch;
  /** How long a fetched mapping set is reused. Default 60 s, matching the service's Cache-Control. */
  mappingsTtlMs?: number;
  /** Ceiling on the mapping fetch and on each token read. Default 3 s. */
  timeoutMs?: number;
  now?: () => number;
};

type MappingsCache = { mappings: Mapping[]; fetchedAt: number };

const MAPPINGS_UNAVAILABLE = 'mappings-unavailable' as const;

export function createTransactionDescriber(options: CreateTransactionDescriberOptions) {
  const ttl = options.mappingsTtlMs ?? 60_000;
  const timeoutMs = options.timeoutMs ?? 3_000;
  const now = options.now ?? (() => Date.now());
  const fetchImpl = () => options.fetch ?? globalThis.fetch.bind(globalThis);

  let cache: MappingsCache | null = null;
  let inflight: Promise<Mapping[]> | null = null;
  const tokens = new Map<string, { info: TokenInfo | null; at: number }>();

  const fetchMappings = async (): Promise<Mapping[]> => {
    const url = `${options.walletApiUrl}/v1/tx-mappings?chainId=${options.chainId}`;
    const response = await withTimeout(fetchImpl()(url, { cache: 'no-store' }), timeoutMs, 'mapping fetch');
    if (!response.ok) throw new Error(`mapping fetch failed: ${response.status}`);
    const body = (await response.json()) as { mappings?: unknown };
    return Array.isArray(body.mappings) ? (body.mappings as Mapping[]) : [];
  };

  /** Fresh cache → reuse; otherwise fetch (once, shared); on failure → stale cache or built-ins only. */
  const loadMappings = async (): Promise<{ mappings: Mapping[]; unavailable: boolean }> => {
    if (cache && now() - cache.fetchedAt < ttl) return { mappings: cache.mappings, unavailable: false };
    inflight ??= fetchMappings().finally(() => {
      inflight = null;
    });
    try {
      const mappings = await inflight;
      cache = { mappings, fetchedAt: now() };
      return { mappings, unavailable: false };
    } catch {
      // A stale set is still the tenant's own words; built-ins alone are the last resort.
      if (cache) return { mappings: cache.mappings, unavailable: false };
      return { mappings: [], unavailable: true };
    }
  };

  const resolveToken = async (_chainId: number, address: string): Promise<TokenInfo | null> => {
    const key = address.toLowerCase();
    const cached = tokens.get(key);
    if (cached && now() - cached.at < ttl) return cached.info;
    let info: TokenInfo | null = null;
    try {
      const token = address as `0x${string}`;
      const [symbol, decimals] = await withTimeout(
        Promise.all([
          options.publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'symbol' }),
          options.publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'decimals' }),
        ]),
        timeoutMs,
        'token metadata read',
      );
      if (typeof symbol === 'string' && symbol.length > 0 && Number.isInteger(decimals)) {
        info = { symbol, decimals: Number(decimals) };
      }
    } catch {
      info = null;
    }
    tokens.set(key, { info, at: now() });
    return info;
  };

  return async function describeTransaction(tx: TransactionRequest): Promise<TransactionDescription> {
    const { mappings, unavailable } = await loadMappings();
    const description = await describeWithLibrary(
      { chainId: options.chainId, to: tx.to, value: tx.value, data: tx.data },
      { mappings, nativeCurrency: options.nativeCurrency, resolveToken },
    );
    if (unavailable) {
      description.warnings.unshift({
        code: MAPPINGS_UNAVAILABLE,
        message: "the application's transaction mappings could not be loaded; only generic descriptions are available",
      });
    }
    return description;
  };
}

function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
