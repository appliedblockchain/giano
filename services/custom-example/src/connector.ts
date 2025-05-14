import { singleKeyAccountFactoryAbi } from '@appliedblockchain/giano-contracts';
import type { WalletDetailsParams } from '@rainbow-me/rainbowkit';
import type { Address } from 'viem';
import { zeroAddress } from 'viem';
import { createPublicClient, toHex } from 'viem';
import { readContract } from 'viem/actions';
import type { CreateConnectorFn } from 'wagmi';
import { createConnector } from 'wagmi';

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };
type PublicKeyAttestation = PublicKeyCredential & { response: AuthenticatorAttestationResponse };

type CreateGianoConnectorParams = {
  details: WalletDetailsParams;
  initialChainId: number;
};

const getCredential = async (): Promise<PublicKeyAssertion | null> => {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  try {
    return (await navigator.credentials.get({
      publicKey: {
        challenge,
      },
    })) as PublicKeyAssertion | null;
  } catch (error) {
    if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
      return null;
    }
    throw error;
  }
};

const createCredential = async (): Promise<PublicKeyAttestation | null> => {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  return (await navigator.credentials.create({
    publicKey: {
      rp: {
        id: window.location.hostname,
        name: 'Giano',
      },
      pubKeyCredParams: [
        {
          type: 'public-key',
          alg: -7,
        },
      ],
      user: {
        id: new TextEncoder().encode(crypto.randomUUID()),
        displayName: 'Giano Credential',
        name: 'giano',
      },
      challenge,
    },
  })) as PublicKeyAttestation | null;
};

export function gianoConnector({ details, initialChainId }: CreateGianoConnectorParams): CreateConnectorFn {
  let chainId = initialChainId;
  let account: Address | null;
  const FACTORY_ADDRESS = '0x35Df176c6e216003A356159E1edF76A0647C828D';

  console.log({ details });

  return createConnector((config) => ({
    id: 'giano',
    name: 'Giano Connector',
    type: 'custom',
    connect: async (params) => {
      try {
        let credential: PublicKeyAttestation | PublicKeyAssertion | null = await getCredential();
        if (!credential) {
          credential = await createCredential();
          if (!credential) {
            throw new Error('Could not obtain credential');
          }
        }

        const chain = config.chains.find((chain) => chain.id === chainId);
        if (!chain) {
          throw new Error('Unknown chain');
        }
        const transports = config.transports ?? {};
        const transport = transports[chain.id];
        if (!transport) {
          throw new Error('No transport for chain');
        }

        const factoryContract = Object.freeze({
          address: FACTORY_ADDRESS,
          abi: singleKeyAccountFactoryAbi,
        });
        const client = createPublicClient({ chain, transport });
        if (credential.response instanceof AuthenticatorAttestationResponse) {
          const publicKey = credential.response.getPublicKey();
          if (!publicKey) {
            throw new Error('Could not obtain public key');
          }
          const x = new Uint8Array(publicKey.slice(-64, -32));
          const y = new Uint8Array(publicKey.slice(-32));
          account = await readContract(client, {
            ...factoryContract,
            functionName: 'getAccountAddress',
            args: [{ x: toHex(x), y: toHex(y) }],
          });
        } else {
          const user = await readContract(client, {
            ...factoryContract,
            functionName: 'getUser',
            args: [toHex(new Uint8Array(credential.rawId))],
          });
          if (user.account === zeroAddress) {
            throw new Error('User not found');
          }
          account = user.account;
        }
        if (params?.chainId) {
          chainId = params.chainId;
        }
        return {
          accounts: [account],
          chainId,
        };
      } catch (e) {
        console.error('connect error', e);
        throw e;
      }
    },
    disconnect: () => {
      console.log('disconnect');
      account = null;
      chainId = null;
      return Promise.resolve();
    },
    getAccounts: async () => {
      console.log('getAccounts called');
      return Promise.resolve(account ? [account] : []);
    },
    getProvider: async () => {
      console.log('getProvider');
      return Promise.resolve({
        request: () => {
          console.log('request...');
        },
      });
    },
    isAuthorized: async () => {
      // todo: leverage localStorage to restore connection status?
      const authorized = Promise.resolve(!!account);
      console.log('isAuthorized called', authorized);
      return Promise.resolve(authorized);
    },
    setup: async () => {
      console.log('setup called');
      return Promise.resolve();
    },
    switchChain: async (params) => {
      console.log('switch chain', params);
      return Promise.resolve();
    },
    getChainId: async () => {
      console.log('getChainId', chainId);
      return chainId;
    },
    onAccountsChanged: (accounts: string[]) => {
      console.log('onAccountsChanged called');
    },
    onChainChanged: (chainId: string) => {
      console.log('onChainChanged called');
    },
    onDisconnect: () => {
      console.log('onDisconnect called');
    },
    ...details,
  }));
}
