import { createGianoConnector, createGianoProvider } from '@appliedblockchain/giano-connector/embedded';
import type { Address, Hex, Transport } from 'viem';
import { custom, http, parseGwei } from 'viem';
import type {
  BundlerClient,
  GetPaymasterDataReturnType,
  GetPaymasterStubDataReturnType,
} from 'viem/account-abstraction'
import { createBundlerClient } from 'viem/account-abstraction';
import { createConfig } from 'wagmi';
import type { Chain } from 'wagmi/chains';
import { base, baseSepolia, hardhat } from 'wagmi/chains';
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

const sdrTestNet = {
  id: 381185,
  name: 'SilentDataRollup Testnet',
  testnet: true,
  nativeCurrency: {
    // this should be same as ethereum
    name: 'Ether',
    symbol: 'ETH',
    decimals: 18,
  },
  rpcUrls: {
    default: {
      http: ['https://testnet.silentdata.com/ec7e8b3eb491df99357e4cb7903cbc21'],
    },
  },
  blockExplorers: {
    default: {
      name: 'SilentDataRollup Explorer',
      url: 'https://explorer-testnet.rollup.silentdata.com/',
    },
  },
} satisfies Chain;

// TODO this is creating creating instances for all options unnecessarily
const configMap: ConfigMap = {
  hardhat: {
    chain: hardhat,
    transport: http('/api/proxy/hardhat'),
    bundler: createBundlerClient({
      chain: hardhat,
      transport: http('/api/proxy/bundler'),
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
    transport: http(envConfig.bundlerRpcUrl),
    bundler: createBundlerClient({
      chain: baseSepolia,
      transport: http(envConfig.bundlerRpcUrl),
      paymaster: true,
    }),
  },
  base: {
    chain: base,
    transport: http(envConfig.bundlerRpcUrl),
    bundler: createBundlerClient({
      chain: base,
      transport: http(envConfig.bundlerRpcUrl),
      paymaster: true,
    }),
  },
  'sdr-testnet': {
    chain: sdrTestNet,
    transport: http(),
    bundler: createBundlerClient({
      chain: sdrTestNet,
      transport: http(envConfig.bundlerRpcUrl),
      paymaster: {
        getPaymasterData: async () => ({
          paymaster: envConfig.paymasterAddress as Address,
          paymasterData: '0x',
          paymasterVerificationGasLimit: BigInt(100_000),
          paymasterPostOpGasLimit: BigInt(80_000),
        }),
        getPaymasterStubData: async () => ({
          paymaster: envConfig.paymasterAddress as Address,
          paymasterData: '0x',
          paymasterVerificationGasLimit: BigInt(100_000),
          paymasterPostOpGasLimit: BigInt(80_000),
          isFinal: true,
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
};

const rpcs = <const>{
  chains: [configMap[envConfig.configKey].chain],
  transports: {
    [configMap[envConfig.configKey].chain.id]: configMap[envConfig.configKey].transport,
  },
};

export const bundlerClient = configMap[envConfig.configKey].bundler;

export const { gianoClient, gianoProvider } = createGianoProvider({
  bundler: bundlerClient,
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

export const useGiano = () => {
  return { gianoConnector, gianoClient, gianoProvider, bundlerClient };
};
