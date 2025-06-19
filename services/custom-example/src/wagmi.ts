import {
  createGianoConnector,
  createGianoProvider
} from '@appliedblockchain/giano-connector'
import { custom, http } from 'viem'
import { createBundlerClient } from 'viem/account-abstraction'
import { createConfig } from 'wagmi'
import { hardhat } from 'wagmi/chains'
import { gianoLocalStorageInjection } from './giano-local-storage-injection'

const rpcs = <const>{
  chains: [hardhat],
  transports: {
    [hardhat.id]: http('http://localhost:8545/'),
  },
}

const bundler = createBundlerClient({
  chain: hardhat,
  transport: http('http://localhost:4337/proxy/rpc'),
})

export const { gianoClient, gianoProvider } = createGianoProvider({
  bundler,
  paymaster: '0x0A8285879FD97FBe15f9402fDED9511Ef3Abf04d',
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: hardhat.id,
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
  ssr: false,
})

export const gianoConnector = config.connectors[0]
