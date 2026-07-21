/**
 * DEMO: wagmi configuration backed by the giano-wallet-api service.
 *
 * The reference `createWalletApiInjection` maps the GianoProviderInjection seam onto
 * the wallet-api: server-side WebAuthn verification, DB-backed credentials and
 * sessions, and policied user-operation relay. Run the service with
 * `docker compose -f deploy/docker-compose.dev.yml up` (or `pnpm dev` in
 * services/wallet-api) and OPEN_REGISTRATION=true for this demo.
 */

import { createGianoConnector, createGianoProvider, createWalletApiInjection, type WalletApiInjection } from '@appliedblockchain/giano-connector/embedded';
import type { Address, Hex, Transport } from 'viem';
import { custom, http, parseGwei } from 'viem';
import type { BundlerClient } from 'viem/account-abstraction';
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import type { Chain } from 'wagmi/chains';
import { baseSepolia, hardhat } from 'wagmi/chains';
import { config as envConfig } from './config';

type ConfigMap = Record<
  string,
  {
    chain: Chain;
    transport: Transport;
    bundler: BundlerClient;
  }
>;

const configMap: ConfigMap = {
  hardhat: {
    chain: hardhat,
    transport: http('/api/proxy/hardhat'),
    bundler: createBundlerClient({
      chain: hardhat,
      transport: http('/api/proxy/bundler'),
      paymaster: {
        //@ts-ignore - the "required" fields are not needed to fulfill a user op
        getPaymasterData: async () => ({
          paymaster: envConfig.paymasterAddress as Address,
        }),
        //@ts-ignore - the "required" fields are not needed to fulfill a user op
        getPaymasterStubData: async () => ({
          paymaster: envConfig.paymasterAddress as Address,
        }),
      },
      userOperation: {
        estimateFeesPerGas: async () => {
          return {
            maxFeePerGas: parseGwei('200'),
            maxPriorityFeePerGas: parseGwei('400'),
          };
        },
      },
    }),
  },
  baseSepolia: {
    chain: baseSepolia,
    transport: http(envConfig.bundlerRpcUrl),
    bundler: createBundlerClient({
      chain: baseSepolia,
      transport: http(envConfig.bundlerRpcUrl),
      paymaster: true,
    }),
  },
};

const rpcs = <const>{
  chains: [configMap[envConfig.configKey].chain],
  transports: {
    [configMap[envConfig.configKey].chain.id]: configMap[envConfig.configKey].transport,
  },
};

const injections = new Map<string, WalletApiInjection>();

/** The wallet-api injection for a user (kept so the demo UI can read session state). */
export function getWalletApiInjection(userId: string): WalletApiInjection {
  let injection = injections.get(userId);
  if (!injection) {
    injection = createWalletApiInjection({
      apiUrl: envConfig.walletApiUrl,
      externalUserId: userId,
      sessionToken: typeof window !== 'undefined' ? window.sessionStorage.getItem(`giano-session:${userId}`) : null,
      onSessionChanged: (token) => {
        if (typeof window === 'undefined') return;
        if (token) window.sessionStorage.setItem(`giano-session:${userId}`, token);
        else window.sessionStorage.removeItem(`giano-session:${userId}`);
      },
    });
    injections.set(userId, injection);
  }
  return injection;
}

/**
 * DEMO: wagmi config for a specific user id. In a real app the external user id
 * comes from your authentication system, and ceremony options are granted by your
 * backend (see `getRegistrationGrant`) instead of OPEN_REGISTRATION=true.
 */
export function createServerConfigForUser(userId: string) {
  const { gianoProvider } = createGianoProvider({
    bundler: configMap[envConfig.configKey].bundler,
    chains: rpcs.chains,
    transports: rpcs.transports,
    initialChainId: configMap[envConfig.configKey].chain.id,
    injection: getWalletApiInjection(userId),
    gianoSmartWalletFactoryAddress: envConfig.gianoSmartWalletFactoryAddress as Hex,
  });

  const providerTransport = custom(gianoProvider);
  const connectorFn = createGianoConnector({ provider: gianoProvider });

  return createConfig({
    chains: [...rpcs.chains],
    transports: {
      ...Object.fromEntries(Object.keys(rpcs.transports).map((k) => [k, providerTransport])),
    },
    connectors: [connectorFn],
    // wagmi persistence off: session/credential state lives in the wallet-api
    storage: null,
  });
}
