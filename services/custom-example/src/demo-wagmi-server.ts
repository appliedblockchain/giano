/**
 * DEMO: Wagmi configuration with server-side storage
 *
 * ⚠️ This is for demonstration purposes only!
 * In production, you'd implement proper authentication, user management,
 * and likely use a different storage strategy (database, etc.)
 */

import { createGianoConnector, createGianoProvider } from '@appliedblockchain/giano-connector';
import { custom, http } from 'viem';
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import { hardhat } from 'wagmi/chains';
import { config as envConfig } from './config';
import { createUserServerInjection } from './demo-server-injection';
import { ServerStorage } from './storage-implementations';

const rpcs = <const>{
  chains: [hardhat],
  transports: {
    [hardhat.id]: http('http://localhost:8545/'),
  },
};

const bundler = createBundlerClient({
  chain: hardhat,
  transport: http(envConfig.bundlerRpcUrl),
});

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
    bundler,
    paymaster: envConfig.paymasterAddress,
    chains: rpcs.chains,
    transports: rpcs.transports,
    initialChainId: hardhat.id,
    injection: userInjection,
    gianoSmartWalletFactoryAddress: envConfig.gianoSmartWalletFactoryAddress,
    storage: userSessionStorage,
  });

  const providerTransport = custom(gianoProvider);
  const connectorFn = createGianoConnector({ provider: gianoProvider });

  return createConfig({
    chains: [...rpcs.chains],
    // @ts-expect-error typing error for being custom transport
    transports: {
      ...Object.fromEntries(Object.keys(rpcs.transports).map((k) => [k, providerTransport])),
    },
    connectors: [connectorFn],
  });
}
