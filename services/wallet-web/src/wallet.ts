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
import type { WalletConfig } from './config';

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
 * Chooses how gas is paid for.
 *
 * `off` returns nothing at all, so the wallet behaves exactly as the unsponsored path does today
 * rather than erroring (R-09). `test-paymaster` is the permissive shim, which needs no service
 * because it approves everything — development and tests only. `service` speaks ERC-7677 to the
 * sponsorship service, which decides per transaction and bills the tenant.
 */
function paymasterHooks(config: WalletConfig) {
  if (config.sponsorship === 'off') return {};

  if (config.sponsorship === 'test-paymaster') {
    if (!config.testPaymasterAddress) {
      throw new Error("sponsorship is 'test-paymaster' but no testPaymasterAddress is configured");
    }
    const paymaster = config.testPaymasterAddress;
    // The permissive paymaster sponsors everything, so the remaining fields are not needed.
    return {
      paymaster: {
        getPaymasterData: async () => ({ paymaster }) as never,
        getPaymasterStubData: async () => ({ paymaster }) as never,
      },
    };
  }

  const client = createErc7677PaymasterClient({
    url: config.paymasterServiceUrl,
    chainId: config.chainId,
    getSessionToken: () => localStorage.getItem(SESSION_KEY),
  });
  return {
    paymaster: {
      getPaymasterData: client.getPaymasterData as never,
      getPaymasterStubData: client.getPaymasterStubData as never,
    },
  };
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
  provider: GianoProvider;
  injection: WalletApiInjection;
  chainId: number;
  externalUserId: string;
  /**
   * Asks the rules engine whether this transaction would be sponsored — *before* the user is
   * offered an approve button, and therefore before any passkey prompt.
   *
   * Today the consent gate shows "Approve" first and builds the operation afterwards, so a
   * refusal discovered while building would arrive after the user had already approved. Asking
   * here is what makes a refusal reach them in time.
   */
  checkSponsorship: (tx: TransactionRequest) => Promise<SponsorshipPreflight>;
};

export function createWalletRuntime(config: WalletConfig): WalletRuntime {
  const chain = defineChain({
    id: config.chainId,
    name: `chain-${config.chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [config.rpcUrl] } },
  });

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
  });

  // Real fee estimation from the chain — without this, giano-wallet-core falls back to a
  // hardcoded 200 gwei maxFeePerGas, which on low-fee chains (e.g. Sepolia ~1 gwei) inflates
  // the required paymaster prefund ~180× and trips "AA31 paymaster deposit too low".
  const publicClient = createPublicClient({ chain, transport: http(config.rpcUrl) });
  const estimateFeesPerGas = async () => {
    try {
      const { maxFeePerGas, maxPriorityFeePerGas } = await publicClient.estimateFeesPerGas();
      return { maxFeePerGas, maxPriorityFeePerGas };
    } catch {
      // non-EIP-1559 chain: fall back to legacy gas price
      const gasPrice = await publicClient.getGasPrice();
      return { maxFeePerGas: gasPrice * 2n, maxPriorityFeePerGas: gasPrice };
    }
  };

  const bundler = createBundlerClient({
    chain,
    transport: http(config.bundlerUrl),
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
    ...paymasterHooks(config),
  });


  const { gianoProvider } = createGianoProvider({
    initialChainId: config.chainId,
    bundler,
    chains: [chain],
    transports: { [config.chainId]: http(config.rpcUrl) },
    injection,
    gianoSmartWalletFactoryAddress: config.factoryAddress,
    estimateFeesPerGas,
  });

  const sponsorshipClient =
    config.sponsorship === 'service'
      ? createErc7677PaymasterClient({
          url: config.paymasterServiceUrl,
          chainId: config.chainId,
          getSessionToken: () => localStorage.getItem(SESSION_KEY),
        })
      : undefined;

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
      // what will actually be submitted. Re-encoding it here by hand is how the pre-flight and
      // the real decision come to disagree.
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

  return { provider: gianoProvider, injection, chainId: config.chainId, externalUserId, checkSponsorship };
}

function toPreflight(check: SponsorshipCheck): SponsorshipPreflight {
  if (check.sponsored) return { state: 'sponsored' };
  // R-21. An outage and a rule refusal call for completely different things from the user — one is
  // "try again in a minute", the other is "this will never work". They must not share a state.
  if (check.reason === 'temporarily-unavailable') return { state: 'unavailable', message: check.message };
  return { state: 'refused', reason: check.reason, message: check.message, ruleResults: check.ruleResults };
}
