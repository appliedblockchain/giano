import {
  createGianoConnector,
  createGianoProvider
} from '@appliedblockchain/giano-connector'
import { custom, http } from 'viem'
import { createBundlerClient } from 'viem/account-abstraction'
import { createConfig } from 'wagmi'
import { baseSepolia } from 'wagmi/chains'
import { gianoLocalStorageInjection } from './giano-local-storage-injection'

// const baseSepoliaRpcEndpoint = 'https://base-sepolia.infura.io/v3/22358d2028354afcba8406f1e346a1bd'
const coinbasePaymasterAndBundlerEndpoint = 'https://api.developer.coinbase.com/rpc/v1/base-sepolia/pwFHxQQD4hBHaJUURUMygfdbyAkD4L2c'

const rpcs = <const>{
  chains: [baseSepolia],
  transports: {
    [baseSepolia.id]: http(coinbasePaymasterAndBundlerEndpoint),
  },
}

const bundler = createBundlerClient({
  chain: baseSepolia,
  transport: http(coinbasePaymasterAndBundlerEndpoint),
  paymaster: true,
})

export const { gianoClient, gianoProvider } = createGianoProvider({
  bundler,
  paymaster: undefined,
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: baseSepolia.id,
  injection: gianoLocalStorageInjection,
})

const providerTransport = custom(gianoProvider)

const createGianoConnectorFn = createGianoConnector({ provider: gianoProvider })

export const config = createConfig({
  chains: [...rpcs.chains],
  // @ts-expect-error typing error for being custom transport
  transports: {
    ...Object.fromEntries(
      Object.keys(rpcs.transports).map((k) => {
        return [k, providerTransport]
      }),
    ),
  },
  connectors: [createGianoConnectorFn],
})

export const gianoConnector = config.connectors[0]
