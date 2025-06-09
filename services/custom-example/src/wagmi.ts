import { http, createConfig, custom } from 'wagmi'
import { foundry, hardhat } from 'wagmi/chains'
import { getDefaultConfig } from '@rainbow-me/rainbowkit'
import { createGianoProvider } from '@appliedblockchain/giano-connector'
import { createBundlerClient } from 'viem/account-abstraction'
import { createConnector } from 'wagmi'

const rpcs = {
  chains: [hardhat],
  transports: {
    [hardhat.id]: http('http://localhost:8545/'),
  },
};

const bundler = createBundlerClient({
  chain: hardhat,
  transport: http('http://localhost:4337/proxy/rpc'),
});

export const provider = createGianoProvider({
  bundler,
  paymaster: '0xF870fb34443b281De8411dbab222741CF5a994c2',
  chains: rpcs.chains,
  transports: rpcs.transports,
  initialChainId: hardhat.id,
});


// Custom transport that uses Giano provider
const providerTransport = custom(provider);

// Custom Giano connector for wagmi
function gianoConnector() {
  return createConnector((config) => ({
    id: 'giano',
    name: 'Giano Passkey Wallet',
    type: 'giano',
    
    async connect() {
      const accounts = await provider.request({
        method: 'eth_requestAccounts',
      })
      
      if (!accounts || accounts.length === 0) {
        throw new Error('No accounts returned')
      }

      const chainId = await provider.request({ method: 'eth_chainId' })
      
      return {
        accounts: accounts as `0x${string}`[],
        chainId: parseInt(chainId, 16),
      }
    },

    async disconnect() {
      await provider.request({
        method: 'wallet_revokePermissions',
        params: [{ eth_accounts: {} }],
      })
    },

    async getAccounts() {
      const accounts = await provider.request({ method: 'eth_accounts' })
      return accounts as `0x${string}`[]
    },

    async getChainId() {
      const chainId = await provider.request({ method: 'eth_chainId' })
      return parseInt(chainId, 16)
    },

    async isAuthorized() {
      const accounts = await provider.request({ method: 'eth_accounts' })
      return accounts && accounts.length > 0
    },

    async switchChain({ chainId }) {
      await provider.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: `0x${chainId.toString(16)}` }],
      })
      return foundry // Return the chain object
    },

    onAccountsChanged(accounts) {
      if (accounts.length === 0) {
        this.onDisconnect()
      } else {
        config.emitter.emit('change', {
          accounts: accounts as `0x${string}`[],
        })
      }
    },

    onChainChanged(chainId) {
      config.emitter.emit('change', {
        chainId: parseInt(chainId, 16),
      })
    },

    onDisconnect() {
      config.emitter.emit('disconnect')
    },

    async getProvider() {
      return Promise.resolve(provider)
    },
  }))
}

export const config = createConfig({
  chains: [...rpcs.chains],
  connectors: [
    gianoConnector(),
  ],
  transports: {
    ...Object.fromEntries(
      Object.keys(rpcs.transports).map((k) => {
        return [k, providerTransport];
      }),
    ),
  },
})

// Also export the default RainbowKit config for other wallets
export const rainbowConfig = getDefaultConfig({
  appName: 'Giano Demo',
  projectId: 'YOUR_PROJECT_ID', // You can set this to a real project ID if needed
  chains: [foundry],
  transports: {
    [foundry.id]: http(),
  },
})
