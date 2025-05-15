import { singleKeyAccountFactoryAbi } from '@appliedblockchain/giano-contracts';
import type { WalletDetailsParams } from '@rainbow-me/rainbowkit';
import type { Address, Chain, Hash, TransactionRequest, Transport } from 'viem';
import { createPublicClient, encodeFunctionData, parseEventLogs, toHex, zeroAddress } from 'viem';
import { readContract, waitForTransactionReceipt } from 'viem/actions';
import type { CreateConnectorFn } from 'wagmi';
import { createConnector } from 'wagmi';

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };
type PublicKeyAttestation = PublicKeyCredential & { response: AuthenticatorAttestationResponse };

export type SendTransactionFnParams = {
  chain: Chain;
  transport: Transport;
  request: TransactionRequest;
};
export type CreateGianoConnectorParams = {
  details: WalletDetailsParams;
  initialChainId: number;
  sendTransaction: (params: SendTransactionFnParams) => Promise<Hash>;
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

function base64UrlToBase64(u: string) {
  return u.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((u.length + 3) % 4);
}

function base64ToBytes(base64: string) {
  const binString = atob(base64UrlToBase64(base64));
  return Uint8Array.from(binString, (m) => m.codePointAt(0) as number);
}

const extractKeyCoordinates = async (spki: ArrayBuffer) => {
  const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, []);
  const { x, y } = await crypto.subtle.exportKey('jwk', key);
  return { x: base64ToBytes(x!), y: base64ToBytes(y!) };
};

export function gianoConnector({ details, initialChainId, sendTransaction }: CreateGianoConnectorParams): CreateConnectorFn {
  let chainId = initialChainId;
  let account: Address | null;
  const FACTORY_ADDRESS = '0x35Df176c6e216003A356159E1edF76A0647C828D';

  const factoryContract = Object.freeze({
    address: FACTORY_ADDRESS,
    abi: singleKeyAccountFactoryAbi,
  });

  return createConnector((config) => ({
    id: 'giano',
    name: 'Giano Connector',
    type: 'custom',
    connect: async (params) => {
      if (params?.chainId) {
        chainId = params.chainId;
      }
      try {
        const chain = config.chains.find((chain) => chain.id === chainId);
        if (!chain) {
          throw new Error(`Unknown chain: ${chainId}`);
        }
        const transports = config.transports ?? {};
        const transport = transports[chain.id];
        if (!transport) {
          throw new Error('No transport for chain');
        }
        const publicClient = createPublicClient({ chain, transport });

        let credential: PublicKeyAttestation | PublicKeyAssertion | null = await getCredential();
        if (!credential) {
          credential = await createCredential();
          if (!credential) {
            throw new Error('Could not obtain credential');
          }
          const publicKey = credential.response.getPublicKey();
          if (!publicKey) {
            throw new Error('Could not obtain public key');
          }
          const { x, y } = await extractKeyCoordinates(publicKey);
          account = await readContract(publicClient, {
            ...factoryContract,
            functionName: 'getAccountAddress',
            args: [{ x: toHex(x), y: toHex(y) }],
          });
          const data = encodeFunctionData({
            ...factoryContract,
            functionName: 'createUser',
            args: [toHex(new Uint8Array(credential.rawId)), { x: toHex(x), y: toHex(y) }],
          });
          const hash = await sendTransaction({
            transport,
            chain,
            request: {
              to: factoryContract.address,
              data,
            },
          });
          console.log({ hash });
          const receipt = await waitForTransactionReceipt(publicClient, { hash });
          console.log(receipt.logs);
          const events = parseEventLogs({ abi: factoryContract.abi, logs: receipt.logs });
          console.log('expected account ->', account);
          console.log('created account ->', events);
        }
        if (!account) {
          const user = await readContract(publicClient, {
            ...factoryContract,
            functionName: 'getUser',
            args: [toHex(new Uint8Array(credential.rawId))],
          });
          if (user.account === zeroAddress) {
            throw new Error('User not found');
          }
          account = user.account;
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
      chainId = -1;
      return Promise.resolve();
    },
    getAccounts: async () => {
      console.log('getAccounts called');
      return Promise.resolve(account ? [account] : []);
    },
    getProvider: async () => {
      console.log('getProvider');
      return Promise.resolve({
        request: (params) => {
          console.log('request...', params);
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
      return Promise.resolve(chainId);
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
