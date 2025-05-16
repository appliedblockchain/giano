import { singleKeyAccountAbi, singleKeyAccountFactoryAbi } from '@appliedblockchain/giano-contracts';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import type { WalletDetailsParams } from '@rainbow-me/rainbowkit';
import type { Address, Chain, Hash, TransactionRequest, Transport } from 'viem';
import { custom, EIP1193Provider, encodeAbiParameters, toBytes } from 'viem';
import { createPublicClient, encodeFunctionData, parseEventLogs, toHex, zeroAddress } from 'viem';
import { readContract, waitForTransactionReceipt, writeContract } from 'viem/actions';
import { bytesToBigint } from 'viem/utils';
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

const getCredential = async ({
  id,
  challenge,
}: {
  id?: BufferSource;
  challenge?: BufferSource;
} = {}): Promise<PublicKeyAssertion | null> => {
  if (!challenge) {
    challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
  }

  try {
    return (await navigator.credentials.get({
      publicKey: {
        ...(id && { allowCredentials: [{ id, type: 'public-key' }] }),
        challenge,
      },
    })) as PublicKeyAssertion | null;
  } catch (error) {
    if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
      console.error(error);
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

function normalizeSignatureCoordinate(bytes: Uint8Array, componentLength = 32) {
  let normalizedBytes;
  if (bytes.length < componentLength) {
    // In case the bytes are shorter than expected, we need to pad it with leading `0`s.
    normalizedBytes = new Uint8Array(componentLength);
    normalizedBytes.set(bytes, componentLength - bytes.length);
  } else if (bytes.length === componentLength) {
    normalizedBytes = bytes;
  } else if (bytes.length === componentLength + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80) {
    // The bytes contain a leading `0` to encode that the integer is positive. This leading `0`
    // needs to be removed for compatibility with the SubtleCrypto Web Crypto API.
    normalizedBytes = bytes.subarray(1);
  } else {
    throw new Error(`Invalid signature component length ${bytes.length}, expected ${componentLength}`);
  }
  return normalizedBytes;
}

// secp256k1 order
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;

function encodeSignature(assertionResponse: PublicKeyAssertion['response']) {
  const decodedClientDataJson = new TextDecoder().decode(assertionResponse.clientDataJSON);
  const responseTypeLocation = decodedClientDataJson.indexOf('"type":');
  const challengeLocation = decodedClientDataJson.indexOf('"challenge":');
  const parsedSignature = AsnParser.parse(assertionResponse.signature, ECDSASigValue);
  const { r, s } = parsedSignature;

  const [normalizedR, normalizedS] = [normalizeSignatureCoordinate(new Uint8Array(r)), normalizeSignatureCoordinate(new Uint8Array(s))];

  const numericS = bytesToBigint(normalizedS);

  // Normalize s to the lower value to prevent signature malleability
  const nonMalleableS = toHex(numericS > HALF_N ? N - numericS : normalizedS, { size: 32 });

  return encodeAbiParameters(
    [
      {
        type: 'tuple',
        components: [
          { type: 'bytes' }, // authenticatorData
          { type: 'string' }, // clientDataJSON
          { type: 'uint256' }, // challengeLocation
          { type: 'uint256' }, // responseTypeLocation
          { type: 'bytes32' }, // r
          { type: 'bytes32' }, // s
        ],
      },
    ],
    [
      [
        toHex(new Uint8Array(assertionResponse.authenticatorData)),
        decodedClientDataJson,
        BigInt(challengeLocation),
        BigInt(responseTypeLocation),
        toHex(normalizedR, { size: 32 }),
        nonMalleableS,
      ],
    ],
  );
}

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
  let connectedCredential: PublicKeyCredential | null;
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
        connectedCredential = credential;
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
      return Promise.resolve(
        custom({
          request: async ({ method, params }) => {
            switch (method) {
              case 'eth_sendTransaction':
                try {
                  const [args] = params;
                  const chain = config.chains.find((chain) => chain.id === chainId);
                  if (!chain) {
                    throw new Error(`Unknown chain: ${chainId}`);
                  }
                  const transports = config.transports ?? {};
                  const transport = transports[chain.id];
                  if (!transport) {
                    throw new Error('No transport for chain');
                  }
                  const client = createPublicClient({ transport, chain });
                  const call = {
                    target: args.to,
                    data: args.data,
                    value: args.value || 0,
                  };
                  const challenge = await readContract(client, {
                    address: account!,
                    abi: singleKeyAccountAbi,
                    functionName: 'getChallenge',
                    args: [call],
                  });
                  console.log('before get cred');
                  const credential = await getCredential({
                    id: connectedCredential!.rawId,
                    challenge: new Uint8Array(toBytes(challenge)),
                  });
                  if (!credential) {
                    console.log('oopsie will throw');
                    throw new Error('Error signing challenge!');
                  }
                  console.log('after get cred');
                  const encodedSignature = encodeSignature(credential.response);
                  const gianoExecuteData = encodeFunctionData({
                    abi: singleKeyAccountAbi,
                    functionName: 'execute',
                    args: [
                      {
                        call,
                        signature: encodedSignature,
                      },
                    ],
                  });
                  console.log({ gianoExecuteData });
                  const hash = await sendTransaction({
                    chain,
                    transport,
                    request: {
                      to: account,
                      data: gianoExecuteData,
                    },
                  });
                  // const hash = await sendTransaction({
                  //   chain,
                  //   transport,
                  //   request: {
                  //     ...args,
                  //   },
                  // });
                  return waitForTransactionReceipt(client, { hash });
                } catch (e) {
                  console.error('reqeust error', e);
                  throw e;
                }
            }
            return Promise.resolve();
          },
        })({}),
      );
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
