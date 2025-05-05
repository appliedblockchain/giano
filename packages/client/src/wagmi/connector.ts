import { type ProviderMessage } from 'viem';
import { createConnector } from 'wagmi';

// Sample implementation by Coinbas: https://github.com/wevm/wagmi/blob/main/packages/connectors/src/coinbaseWallet.ts
export const createGianoConnector = (({ chains, emitter }) => {
  return {
    id: 'giano',
    name: 'Giano',
    type: 'custom',
    connect: async () => {
      /* The steps below would probably be performed by the EIP-1193 provider we will need to implement, to mimic Metamask's behavior
	 1. Show UI prompting for wallet creation OR connecting to existing one
	 2a. Creation: request creation of a new passkey to the browser and call the factory to deploy a new account,
	  passing credential ID and public key coordinates (x,y)
	 2b. Connection: request selection of an existing passkey to the browser and try to fetch the public key by passing 
	 the credential ID to the factory
	 3. Store the User struct returned from the factory in the connector's internal state
	 */
      return { accounts: [], chainId: chains[0].id };
    },
    disconnect: async () => {
      // Reset connector state
    },
    getAccounts: async () => {
      // Return the connected account's address
      return Promise.resolve([]);
    },
    getProvider: async () => {
      // Return a singleton EIP-1193(https://eips.ethereum.org/EIPS/eip-1193)-compliant provider that will do the actual
      // low level communication with the contracts. Example implementation by Coinbase for their wallet:  https://github.com/coinbase/coinbase-wallet-sdk/blob/master/packages/wallet-sdk/src/CoinbaseWalletProvider.ts#L22
	  // Probably this provider is where we would implement stuff like calling a faucet or an endpoint to dispatch encoded tx data to
      return Promise.resolve({});
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
