import { createGianoConnector, createGianoProvider } from '@appliedblockchain/giano-connector';
import type { Address, Hex, Transport } from 'viem';
import { custom, http, parseGwei } from 'viem';
import type { BundlerClient, GetPaymasterDataReturnType, GetPaymasterStubDataReturnType, PaymasterActions } from 'viem/account-abstraction';
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import type { Chain } from 'wagmi/chains';
import { baseSepolia, hardhat } from 'wagmi/chains';
import { config as envConfig } from './config';
import { gianoInjection } from './giano-injection';

console.log('Using config:', envConfig);

type ConfigMap = Record<
  string,
  {
    chain: Chain;
    transport: Transport;
    bundler: BundlerClient;
  }
>;

// TODO this is creating creating instances for all options unnecessarily
const configMap: ConfigMap = {
  hardhat: {
    chain: hardhat,
    transport: http('http://localhost:8545/'),
    bundler: createBundlerClient({
      chain: hardhat,
      transport: http(envConfig.bundlerRpcUrl),
      paymaster: {
        //@ts-ignore - the "required" fields are not needed to fulfill a user op
        getPaymasterData: async (): Promise<GetPaymasterDataReturnType> => ({
          paymaster: envConfig.paymasterAddress as Address,
        }),
        //@ts-ignore - the "required" fields are not needed to fulfill a user op
        getPaymasterStubData: async (): Promise<GetPaymasterStubDataReturnType> => ({
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
  sdrTestnet: {
    chain: {
      id: 381185,
      name: 'SDR Testnet',
      nativeCurrency: {
        name: 'ETH',
        symbol: 'ETH',
        decimals: 18,
      },
      rpcUrls: {
        default: { http: ['https://testnet.silentdata.com/ebc4c7a9f6e15c22f8cef53747dc07a8'] },
      },
      blockExplorers: {
        default: { name: 'SilentData', url: 'https://testnet.silentdata.com' },
      },
      testnet: true,
    },
    transport: http('https://testnet.silentdata.com/ebc4c7a9f6e15c22f8cef53747dc07a8'),
    bundler: createBundlerClient({
      chain: hardhat,
      transport: http(envConfig.bundlerRpcUrl),
      paymaster: {
        //@ts-ignore - the "required" fields are not needed to fulfill a user op
        getPaymasterData: async (): Promise<GetPaymasterDataReturnType> => ({
          paymaster: envConfig.paymasterAddress as Address,
        }),
        //@ts-ignore - the "required" fields are not needed to fulfill a user op
        getPaymasterStubData: async (): Promise<GetPaymasterStubDataReturnType> => ({
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

export const { gianoClient, gianoProvider } = createGianoProvider({
  bundler: configMap[envConfig.configKey].bundler,
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: configMap[envConfig.configKey].chain.id,
  injection: gianoInjection,
  gianoSmartWalletFactoryAddress: envConfig.gianoSmartWalletFactoryAddress as Hex,
});

const providerTransport = custom(gianoProvider);

const createGianoConnectorFn = createGianoConnector({ provider: gianoProvider });

export const config = createConfig({
  chains: [...rpcs.chains],
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
