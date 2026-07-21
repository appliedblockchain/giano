import { createGianoProvider, createWalletApiInjection, type GianoProvider, type WalletApiInjection } from '@appliedblockchain/giano-wallet-core';
import { defineChain, http } from 'viem';
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

export type WalletRuntime = {
  provider: GianoProvider;
  injection: WalletApiInjection;
  chainId: number;
  externalUserId: string;
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

  const bundler = createBundlerClient({
    chain,
    transport: http(config.bundlerUrl),
  });

  const { gianoProvider } = createGianoProvider({
    initialChainId: config.chainId,
    bundler,
    chains: [chain],
    transports: { [config.chainId]: http(config.rpcUrl) },
    injection,
    gianoSmartWalletFactoryAddress: config.factoryAddress,
  });

  return { provider: gianoProvider, injection, chainId: config.chainId, externalUserId };
}
