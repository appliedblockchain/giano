import { createGianoProvider, createWalletApiInjection, type GianoProvider, type WalletApiInjection } from '@appliedblockchain/giano-wallet-core';
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

export type WalletRuntime = {
  provider: GianoProvider;
  injection: WalletApiInjection;
};

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

  const bundler = createBundlerClient({
    chain,
    transport: http(CONFIG.bundlerUrl),
    ...(CONFIG.paymasterAddress
      ? {
          paymaster: {
            // permissive/testing paymaster: sponsor everything
            getPaymasterData: async () => ({ paymaster: CONFIG.paymasterAddress! }) as never,
            getPaymasterStubData: async () => ({ paymaster: CONFIG.paymasterAddress! }) as never,
          },
        }
      : {}),
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

  const { gianoProvider } = createGianoProvider({
    initialChainId: CONFIG.chainId,
    bundler,
    chains: [chain],
    transports: { [CONFIG.chainId]: http(CONFIG.rpcUrl) },
    injection,
    gianoSmartWalletFactoryAddress: CONFIG.factoryAddress,
    estimateFeesPerGas,
  });

  return { provider: gianoProvider, injection };
}
