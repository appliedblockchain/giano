import type {
  MetaMaskSDK,
  MetaMaskSDKOptions,
  RPC_URLS_MAP,
  SDKProvider,
} from '@metamask/sdk'
import {
  ChainNotConfiguredError,
  type EIP1193Provider } from 'viem';
import { type ProviderMessage } from 'viem';
import { createConnector } from 'wagmi';
import { createGianoEIP1193Provider } from '../provider';
import { hardhat } from 'viem/chains';

// Sample implementation by Coinbas: https://github.com/wevm/wagmi/blob/main/packages/connectors/src/coinbaseWallet.ts
const createGianoConnector = createConnector<EIP1193Provider>(({ chains, transports, emitter }) => {
  return {
    id: 'giano',
    name: 'Giano',
    type: 'custom',
    async connect(props) {
      const provider = await this.getProvider();
      const chainId = props?.chainId || hardhat.id;
      const transport = transports?.[chainId] ?? http();
      const accounts = await provider.request({ method: 'eth_requestAccounts' });
      return { accounts, chainId: chains[0].id };
    },
    disconnect: async () => {
      // Reset connector state
    },
    getAccounts: async () => {
      // Return the connected account's address
      return Promise.resolve([]);
    },
    getProvider: async (): Promise<EIP1193Provider> => {
      return Promise.resolve(provider);
    },
    getChainId: async () => {
      return Promise.resolve(chains[0].id);
    },
    isAuthorized: async () => {
      // Return true if the connector's internal state is set, false otherwise
      return false;
    },
    onAccountsChanged: () => {},
    onChainChanged: () => {},
    onDisconnect: () => {},
  };
});
