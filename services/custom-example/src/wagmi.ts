import { createGianoConnector, createGianoProvider } from '@appliedblockchain/giano-connector';
import { custom, http } from 'viem';
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import { baseSepolia, hardhat } from 'wagmi/chains';
import { config as envConfig } from './config';
import { gianoLocalStorageInjection } from './giano-local-storage-injection';

console.log('Using config:', envConfig);

const configMap = {
  hardhat: {
    chain: hardhat,
    transport: http('http://localhost:8545/'),
    bundlerRpcUrl: http(envConfig.bundlerRpcUrl),
  },
  baseSepolia: {
    chain: baseSepolia,
    transport: http('https://api.developer.coinbase.com/rpc/v1/base-sepolia/pwFHxQQD4hBHaJUURUMygfdbyAkD4L2c'),
    bundlerRpcUrl: http(envConfig.bundlerRpcUrl),
  },
};

const rpcs = <const>{
  chains: [configMap[envConfig.configKey].chain],
  transports: {
    [configMap[envConfig.configKey].chain.id]: configMap[envConfig.configKey].transport,
  },
};

const bundler = createBundlerClient({
  chain: configMap[envConfig.configKey].chain,
  transport: configMap[envConfig.configKey].bundlerRpcUrl,
  paymaster: envConfig.configKey === 'hardhat' ? undefined : true,
});

export const { gianoClient, gianoProvider } = createGianoProvider({
  bundler,
  paymaster: envConfig.paymasterAddress,
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: configMap[envConfig.configKey].chain.id,
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
