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
import { createPublicClient, defineChain, http } from 'viem';
import { createBundlerClient } from 'viem/account-abstraction';
import { CONFIG } from './config';

// Same keys as the stock wallet-web — localStorage is origin-partitioned anyway, and
// keeping the names lets the tenant-isolation suite force a cross-tenant external-id
// collision by setting one key on both wallet origins.
const USER_ID_KEY = 'giano:external-user-id';
const SESSION_KEY = 'giano:session-token';

function getOrCreateExternalUserId(): string {
  let id = localStorage.getItem(USER_ID_KEY);
  if (!id) {
    id = crypto.randomUUID().replace(/-/g, '');
    localStorage.setItem(USER_ID_KEY, id);
  }
  return id;
}

export type SponsorshipPreflight =
  | { state: 'not-applicable' }
  | { state: 'sponsored' }
  | { state: 'refused'; reason: SponsorshipRefusalReason; message: string; ruleResults: SponsorshipRuleResult[] }
  | { state: 'unavailable'; message: string };

export type TransactionRequest = { to?: `0x${string}`; value?: `0x${string}` | bigint; data?: `0x${string}` };

export type WalletRuntime = {
  provider: GianoProvider;
  injection: WalletApiInjection;
  /**
   * Deliberately duplicated from the stock wallet rather than shared: the pre-approval refusal is
   * wallet-side behaviour, and a BYO tenant has to get it right in its own UI. Having the
   * reference implementation do it the same way is what makes it clear that this is a required
   * part of building a wallet origin, not a nicety of Giano's own one.
   */
  checkSponsorship: (tx: TransactionRequest) => Promise<SponsorshipPreflight>;
};

const sponsorshipClient =
  CONFIG.sponsorship === 'service'
    ? createErc7677PaymasterClient({
        url: CONFIG.paymasterServiceUrl,
        chainId: CONFIG.chainId,
        getSessionToken: () => localStorage.getItem(SESSION_KEY),
      })
    : undefined;

function paymasterHooks() {
  if (CONFIG.sponsorship === 'off') return {};
  if (CONFIG.sponsorship === 'test-paymaster') {
    const paymaster = CONFIG.testPaymasterAddress!;
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

/** Vanilla-TS port of services/wallet-web/src/wallet.ts — the whole SDK surface a BYO UI needs. */
export function createWalletRuntime(): WalletRuntime {
  const chain = defineChain({
    id: CONFIG.chainId,
    name: `chain-${CONFIG.chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [CONFIG.rpcUrl] } },
  });

  const injection = createWalletApiInjection({
    apiUrl: CONFIG.walletApiUrl,
    externalUserId: getOrCreateExternalUserId(),
    credentialName: CONFIG.brandName,
    sessionToken: localStorage.getItem(SESSION_KEY),
    onSessionChanged: (token) => {
      if (token) localStorage.setItem(SESSION_KEY, token);
      else localStorage.removeItem(SESSION_KEY);
    },
  });

  // Real fee estimation from the chain — without this, giano-wallet-core falls back to a
  // hardcoded 200 gwei maxFeePerGas, which on low-fee chains inflates the required
  // paymaster prefund ~180× and trips "AA31 paymaster deposit too low". The easiest
  // thing for a BYO UI to lose, and the most important to keep.
  const publicClient = createPublicClient({ chain, transport: http(CONFIG.rpcUrl) });
  const estimateFeesPerGas = async () => {
    try {
      const { maxFeePerGas, maxPriorityFeePerGas } = await publicClient.estimateFeesPerGas();
      return { maxFeePerGas, maxPriorityFeePerGas };
    } catch {
      const gasPrice = await publicClient.getGasPrice();
      return { maxFeePerGas: gasPrice * 2n, maxPriorityFeePerGas: gasPrice };
    }
  };

  const bundler = createBundlerClient({
    chain,
    transport: http(CONFIG.bundlerUrl),
    /*
     * Fees must be resolved *before* the paymaster hooks run, not after.
     *
     * A validating paymaster signs the operation's gas fees, so an authorisation issued while
     * `maxFeePerGas` is still unset would either be refused or — worse — signed over zero and then
     * fail on chain with `AA34` once the real fee was filled in. viem populates fees during
     * `prepareUserOperation` when given this hook, which puts them in place before it asks the
     * paymaster for anything.
     */
    userOperation: { estimateFeesPerGas: async () => estimateFeesPerGas() },
    ...paymasterHooks(),
  });


  const { gianoProvider } = createGianoProvider({
    initialChainId: CONFIG.chainId,
    bundler,
    chains: [chain],
    transports: { [CONFIG.chainId]: http(CONFIG.rpcUrl) },
    injection,
    gianoSmartWalletFactoryAddress: CONFIG.factoryAddress,
    estimateFeesPerGas,
  });

  const checkSponsorship = async (tx: TransactionRequest): Promise<SponsorshipPreflight> => {
    if (!sponsorshipClient) return { state: 'not-applicable' };

    const account = gianoProvider.getSmartAccount();
    if (!account) return { state: 'unavailable', message: 'the wallet is not connected yet' };

    try {
      const callData = await account.encodeCalls([
        { to: tx.to ?? account.address, value: tx.value === undefined ? 0n : BigInt(tx.value), data: tx.data ?? '0x' },
      ]);
      const [nonce, fees] = await Promise.all([account.getNonce(), estimateFeesPerGas()]);
      const check = await sponsorshipClient.checkSponsorship({
        userOperation: {
          sender: account.address,
          nonce,
          callData,
          maxFeePerGas: fees.maxFeePerGas,
          maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
        },
      });
      return toPreflight(check);
    } catch (error) {
      return { state: 'unavailable', message: error instanceof Error ? error.message : 'sponsorship check failed' };
    }
  };

  return { provider: gianoProvider, injection, checkSponsorship };
}

function toPreflight(check: SponsorshipCheck): SponsorshipPreflight {
  if (check.sponsored) return { state: 'sponsored' };
  if (check.reason === 'temporarily-unavailable') return { state: 'unavailable', message: check.message };
  return { state: 'refused', reason: check.reason, message: check.message, ruleResults: check.ruleResults };
}
