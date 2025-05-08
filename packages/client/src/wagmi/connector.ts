import { type EIP1193Provider } from 'viem';
import { type ProviderMessage } from 'viem';
import { createConnector } from 'wagmi';
import { GianoEIP1193Provider } from '../provider';

// Sample implementation by Coinbas: https://github.com/wevm/wagmi/blob/main/packages/connectors/src/coinbaseWallet.ts
const createGianoConnector = createConnector<EIP1193Provider>(({ chains, emitter }) => {
  const provider: EIP1193Provider = GianoEIP1193Provider;
  return {
    id: 'giano',
    name: 'Giano',
    type: 'custom',
    async connect() {
      /* The steps below would probably be performed by the EIP-1193 provider we will need to implement, to mimic Metamask's behavior
	 1. Show UI prompting for wallet creation OR connecting to existing one
	 2a. Creation: request creation of a new passkey to the browser and call the factory to deploy a new account,
	  passing credential ID and public key coordinates (x,y)
	 2b. Connection: request selection of an existing passkey to the browser and try to fetch the public key by passing 
	 the credential ID to the factory
	 3. Store the User struct returned from the factory in the connector's internal state
	 */
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
