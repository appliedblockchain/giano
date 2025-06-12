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
  credentialKeyMapperAddress: '0x297406bb0c4cBDB6A722Cf2728c5592eEd774195',
  gianoSmartWalletFactoryAddress: '0xC932321e8A7DceE09C7F793d0796885aC080DFa5',
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
