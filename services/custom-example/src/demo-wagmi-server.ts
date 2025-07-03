/**
 * DEMO: Wagmi configuration with server-side storage
 *
 * ⚠️ This is for demonstration purposes only!
 * In production, you'd implement proper authentication, user management,
 * and likely use a different storage strategy (database, etc.)
 */

import { createGianoConnector, createGianoProvider } from '@appliedblockchain/giano-connector';
import type { Address, Hex, Transport } from 'viem';
import { custom, http, parseGwei } from 'viem';
import type { BundlerClient } from 'viem/account-abstraction';
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import type { Chain } from 'wagmi/chains';
import { baseSepolia, hardhat } from 'wagmi/chains';
import { config as envConfig } from './config';
import { createUserServerInjection } from './demo-server-injection';
import { ServerStorage } from './storage-implementations';

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
    transport: http('http://localhost:8545/'),
    bundler: createBundlerClient({
      chain: hardhat,
      transport: http(envConfig.bundlerRpcUrl),
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
    transport: http('https://api.developer.coinbase.com/rpc/v1/base-sepolia/pwFHxQQD4hBHaJUURUMygfdbyAkD4L2c'),
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

/**
 * DEMO: Create server storage config for a specific user
 *
 * ⚠️ This is for demonstration purposes only!
 * In a real app, you'd get userId from your authentication system
 */
export function createServerConfigForUser(userId: string) {
  const userInjection = createUserServerInjection(userId);
  const userSessionStorage = new ServerStorage('/api/storage', userId);

  const { gianoProvider } = createGianoProvider({
    bundler: configMap[envConfig.configKey].bundler,
    chains: rpcs.chains,
    transports: rpcs.transports,
    initialChainId: configMap[envConfig.configKey].chain.id,
    injection: userInjection,
    gianoSmartWalletFactoryAddress: envConfig.gianoSmartWalletFactoryAddress as Hex,
    storage: userSessionStorage,
  });

  const providerTransport = custom(gianoProvider);
  const connectorFn = createGianoConnector({ provider: gianoProvider });

  return createConfig({
    chains: [...rpcs.chains],
    transports: {
      ...Object.fromEntries(Object.keys(rpcs.transports).map((k) => [k, providerTransport])),
    },
    connectors: [connectorFn],
  });
}
