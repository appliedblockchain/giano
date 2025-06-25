import { createGianoConnector, createGianoProvider } from '@appliedblockchain/giano-connector';
import { custom, http } from 'viem';
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import { hardhat } from 'wagmi/chains';
import { config as envConfig } from './config';
import { gianoLocalStorageInjection } from './giano-local-storage-injection';

const rpcs = <const>{
  chains: [hardhat],
  transports: {
    [hardhat.id]: http('http://localhost:8545/'),
  },
};

const bundler = createBundlerClient({
  chain: hardhat,
  transport: http(envConfig.bundlerRpcUrl),
})

export const { gianoClient, gianoProvider } = createGianoProvider({
  bundler,
  paymaster: envConfig.paymasterAddress,
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: hardhat.id,
  injection: gianoLocalStorageInjection,
  gianoSmartWalletFactoryAddress: envConfig.gianoSmartWalletFactoryAddress,
});

const providerTransport = custom(gianoProvider);

const createGianoConnectorFn = createGianoConnector({ provider: gianoProvider });

export const config = createConfig({
  chains: [...rpcs.chains],
  // @ts-expect-error typing error for being custom transport
  transports: {
    ...Object.fromEntries(
      Object.keys(rpcs.transports).map((k) => {
        return [k, providerTransport];
      }),
    ),
  },
  connectors: [createGianoConnectorFn],
});

export const gianoConnector = config.connectors[0];
