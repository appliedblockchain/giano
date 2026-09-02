import {
  createErc7677PaymasterClient,
  createGianoProvider,
  createWalletApiInjection,
  type GianoProvider,
  type SponsorshipCheck,
  type SponsorshipRefusalReason,
  type SponsorshipRuleResult,
  type WalletApiInjection,
} from '@appliedblockchain/giano-wallet-core';
import { createPublicClient, defineChain, http, type Chain, type PublicClient } from 'viem';
import { createBundlerClient } from 'viem/account-abstraction';
import type { WalletChainConfig, WalletConfig } from './config';

const USER_ID_KEY = 'giano:external-user-id';
const SESSION_KEY = 'giano:session-token';

/**
 * On the dedicated wallet origin the passkey itself is the identity; the wallet-api
 * external user id is a per-browser stable random id (it only namespaces credentials).
 */
function getOrCreateExternalUserId(): string {
  let id = localStorage.getItem(USER_ID_KEY);
  if (!id) {
    id = crypto.randomUUID().replace(/-/g, '');
    localStorage.setItem(USER_ID_KEY, id);
  }
  return id;
}

/**
 * The answer the review screen needs before it decides whether to offer an approve button.
 *
 * `not-applicable` is its own state rather than a synonym for `sponsored`, because a deployment
 * with sponsorship off should behave exactly as the unsponsored path always did — the user pays,
 * and there is nothing to explain.
 */
export type SponsorshipPreflight =
  | { state: 'not-applicable' }
  | { state: 'sponsored' }
  | { state: 'refused'; reason: SponsorshipRefusalReason; message: string; ruleResults: SponsorshipRuleResult[] }
  | { state: 'unavailable'; message: string };

export type TransactionRequest = { to?: `0x${string}`; value?: `0x${string}` | bigint; data?: `0x${string}` };

export type WalletRuntime = {
  /** The EIP-1193 provider for this chain (from giano-wallet-core). */
  provider: GianoProvider;
  /** The shared wallet-api session, held ONCE across all runtimes (MC-76). */
  injection: WalletApiInjection;
  chainId: number;
  /** Human-readable — what consent screens show (MC-81). */
  chainName: string;
  externalUserId: string;
  /** Read client for THIS chain — what the management view enumerates the owner set with (WM-01). */
  publicClient: PublicClient;
  factoryAddress: `0x${string}`;
  /** True when the smart account has code on THIS chain (deployment is lazy and per chain, MC-29/MC-30). */
  isAccountDeployed: (address: `0x${string}`) => Promise<boolean>;
  /**
   * Asks the rules engine whether this transaction would be sponsored — *before* the user is
   * offered an approve button, and therefore before any passkey prompt (WK-13, WM-68). Evaluated
   * for THIS chain, by this chain's runtime; the answer is never reused across chains (MC-71).
   */
  checkSponsorship: (tx: TransactionRequest) => Promise<SponsorshipPreflight>;
};

export type WalletRuntimes = {
  /** Built on first use, then memoised (WK-02, MC-44): a session that uses one chain costs one chain. */
  runtimeFor: (chainId: number) => WalletRuntime;
  servedChainIds: readonly number[];
  descriptorFor: (chainId: number) => WalletChainConfig;
};

type FeeEstimator = () => Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }>;

/**
 * Chooses how gas is paid for ON ONE CHAIN — sponsorship is configured per chain (MC-65)
 * and a pre-flight answer is never reused across chains (MC-71).
 *
 * `off` returns nothing at all, so the wallet behaves exactly as the unsponsored path does
 * rather than erroring (R-09). `test-paymaster` is the permissive shim, which needs no service
 * because it approves everything — development and tests only (config validation refuses it in
 * production builds, WK-05). `service` speaks ERC-7677 to the sponsorship service, which decides
 * per transaction and bills the tenant.
 */
function paymasterHooks(chain: WalletChainConfig, sponsorshipClient: ReturnType<typeof createErc7677PaymasterClient> | undefined) {
  if (chain.sponsorship === 'off') return {};

  if (chain.sponsorship === 'test-paymaster') {
    if (!chain.testPaymasterAddress) {
      throw new Error(`chain ${chain.chainId}: sponsorship is 'test-paymaster' but no testPaymasterAddress is configured`);
    }
    const paymaster = chain.testPaymasterAddress;
    // The permissive paymaster sponsors everything, so the remaining fields are not needed.
    return {
      paymaster: {
        getPaymasterData: async () => ({ paymaster }) as never,
        getPaymasterStubData: async () => ({ paymaster }) as never,
      },
    };
  }

  return {
    paymaster: {
      getPaymasterData: sponsorshipClient!.getPaymasterData as never,
      getPaymasterStubData: sponsorshipClient!.getPaymasterStubData as never,
    },
  };
}

/**
 * The bundler-client options for one chain, as a pure function so the load-bearing shape is
 * testable (WK-04, WK-27): the fee estimator is ALWAYS wired into `userOperation`, and there is
 * no construction path that attaches paymaster hooks without it.
 *
 * Fees must be resolved *before* the paymaster hooks run, not after. A validating paymaster
 * signs the operation's gas fees, so an authorisation issued while `maxFeePerGas` is still unset
 * would either be refused or — worse — signed over zero and then fail on chain with `AA34` once
 * the real fee was filled in. viem populates fees during `prepareUserOperation` when given this
 * hook, which puts them in place before it asks the paymaster for anything.
 */
export function bundlerOptions(
  chainConfig: WalletChainConfig,
  chain: Chain,
  estimateFeesPerGas: FeeEstimator,
  sponsorshipClient: ReturnType<typeof createErc7677PaymasterClient> | undefined,
) {
  return {
    chain,
    transport: http(chainConfig.bundlerUrl),
    userOperation: { estimateFeesPerGas: async () => estimateFeesPerGas() },
    ...paymasterHooks(chainConfig, sponsorshipClient),
  };
}

/**
 * One runtime per served chain (WK-01, MC-43): its own viem chain, public client, bundler
 * client, paymaster hooks, fee estimator, GianoProvider and sponsorship pre-flight. Nothing is
 * shared between chains except the injection — which is chain-agnostic, holds the wallet-api
 * session (WK-03, MC-76), and must NOT be duplicated: duplicating it would duplicate the
 * session. The kit offers no way to construct a runtime with its own injection.
 */
export function createWalletRuntimes(config: WalletConfig): WalletRuntimes {
  if (!config || !Array.isArray(config.chains) || config.chains.length === 0) {
    throw new Error('wallet config: `chains` must list at least one chain');
  }
  const externalUserId = getOrCreateExternalUserId();

  const injection = createWalletApiInjection({
    apiUrl: config.walletApiUrl,
    externalUserId,
    credentialName: config.branding.name,
    sessionToken: localStorage.getItem(SESSION_KEY),
    onSessionChanged: (token) => {
      if (token) localStorage.setItem(SESSION_KEY, token);
      else localStorage.removeItem(SESSION_KEY);
    },
    // A discoverable sign-in can reveal the credential's canonical external user id (its
    // passkey was added through a cross-device handoff) — persist it so later ceremonies
    // and silent restores on this device list the credential.
    onExternalUserIdChanged: (id) => localStorage.setItem(USER_ID_KEY, id),
  });

  const byId = new Map(config.chains.map((chain) => [chain.chainId, chain]));
  const runtimes = new Map<number, WalletRuntime>();

  const descriptorFor = (chainId: number): WalletChainConfig => {
    const descriptor = byId.get(chainId);
    if (!descriptor) {
      throw new Error(`this wallet does not serve chain ${chainId} (served: ${[...byId.keys()].join(', ')})`);
    }
    return descriptor;
  };

  const runtimeFor = (chainId: number): WalletRuntime => {
    const existing = runtimes.get(chainId);
    if (existing) return existing;
    const runtime = buildRuntime(descriptorFor(chainId), injection, externalUserId);
    runtimes.set(chainId, runtime);
    return runtime;
  };

  return { runtimeFor, servedChainIds: config.chains.map((chain) => chain.chainId), descriptorFor };
}

function buildRuntime(chainConfig: WalletChainConfig, injection: WalletApiInjection, externalUserId: string): WalletRuntime {
  const chain = defineChain({
    id: chainConfig.chainId,
    name: chainConfig.name,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [chainConfig.rpcUrl] } },
  });

  // Real fee estimation from the chain — without this, giano-wallet-core falls back to a
  // hardcoded 200 gwei maxFeePerGas, which on low-fee chains (e.g. Sepolia ~1 gwei) inflates
  // the required paymaster prefund ~180× and trips "AA31 paymaster deposit too low".
  const publicClient = createPublicClient({ chain, transport: http(chainConfig.rpcUrl) });
  const estimateFeesPerGas: FeeEstimator = async () => {
    try {
      const { maxFeePerGas, maxPriorityFeePerGas } = await publicClient.estimateFeesPerGas();
      return { maxFeePerGas, maxPriorityFeePerGas };
    } catch {
      // non-EIP-1559 chain: fall back to legacy gas price
      const gasPrice = await publicClient.getGasPrice();
      return { maxFeePerGas: gasPrice * 2n, maxPriorityFeePerGas: gasPrice };
    }
  };

  const sponsorshipClient =
    chainConfig.sponsorship === 'service'
      ? createErc7677PaymasterClient({
          url: chainConfig.paymasterServiceUrl,
          chainId: chainConfig.chainId,
          getSessionToken: () => localStorage.getItem(SESSION_KEY),
        })
      : undefined;

  const bundler = createBundlerClient(bundlerOptions(chainConfig, chain, estimateFeesPerGas, sponsorshipClient));

  const { gianoProvider } = createGianoProvider({
    initialChainId: chainConfig.chainId,
    bundlers: { [chainConfig.chainId]: bundler },
    chains: [chain],
    transports: { [chainConfig.chainId]: http(chainConfig.rpcUrl) },
    injection,
    factoryAddresses: { [chainConfig.chainId]: chainConfig.factoryAddress },
    estimateFeesPerGas,
  });

  const checkSponsorship = async (tx: TransactionRequest): Promise<SponsorshipPreflight> => {
    if (!sponsorshipClient) return { state: 'not-applicable' };

    const account = gianoProvider.getSmartAccount();
    if (!account) {
      // No account means no session, and the service would refuse anyway — but calling it would
      // surface as "not your wallet", which is not what happened.
      return { state: 'unavailable', message: 'the wallet is not connected yet' };
    }

    try {
      // The account's own encoder, so the calldata the rules engine decodes is byte-identical to
      // what will actually be submitted (WK-14). Re-encoding it here by hand is how the
      // pre-flight and the real decision come to disagree.
      const callData = await account.encodeCalls([
        { to: tx.to ?? account.address, value: tx.value === undefined ? 0n : BigInt(tx.value), data: tx.data ?? '0x' },
      ]);
      const [nonce, fees] = await Promise.all([account.getNonce(), estimateFeesPerGas()]);

      return toPreflight(
        await sponsorshipClient.checkSponsorship({
          userOperation: {
            sender: account.address,
            nonce,
            callData,
            // The fee matters to the answer: the cost cap and the balance check are both denominated
            // in wei, so a wildly wrong fee estimate produces a wildly wrong verdict.
            maxFeePerGas: fees.maxFeePerGas,
            maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
          },
        }),
      );
    } catch (error) {
      return { state: 'unavailable', message: error instanceof Error ? error.message : 'sponsorship check failed' };
    }
  };

  const isAccountDeployed = async (address: `0x${string}`): Promise<boolean> => {
    const code = await publicClient.getCode({ address }).catch(() => undefined);
    return !!code && code !== '0x';
  };

  return {
    provider: gianoProvider,
    injection,
    chainId: chainConfig.chainId,
    chainName: chainConfig.name,
    externalUserId,
    publicClient: publicClient as PublicClient,
    factoryAddress: chainConfig.factoryAddress,
    isAccountDeployed,
    checkSponsorship,
  };
}

function toPreflight(check: SponsorshipCheck): SponsorshipPreflight {
  if (check.sponsored) return { state: 'sponsored' };
  // R-21. An outage and a rule refusal call for completely different things from the user — one is
  // "try again in a minute", the other is "this will never work". They must not share a state.
  if (check.reason === 'temporarily-unavailable') return { state: 'unavailable', message: check.message };
  return { state: 'refused', reason: check.reason, message: check.message, ruleResults: check.ruleResults };
}
