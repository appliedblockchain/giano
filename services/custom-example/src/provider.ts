import { singleKeyAccountAbi, singleKeyAccountFactoryAbi } from '@appliedblockchain/giano-contracts';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import type { PublicClient } from 'viem';
import {
  type Address,
  type Chain,
  createPublicClient,
  type EIP1193Provider,
  encodeAbiParameters,
  encodeFunctionData,
  type Hash,
  maxUint256,
  toBytes,
  toHex,
  type Transport,
  zeroAddress,
} from 'viem';
import { readContract, waitForTransactionReceipt } from 'viem/actions';
import type { EIP1193Parameters } from 'viem/types/eip1193';
import { bytesToBigint } from 'viem/utils';
import { type SendTransactionFnParams } from './connector';

const FACTORY_ADDRESS = '0x35Df176c6e216003A356159E1edF76A0647C828D';

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };
type PublicKeyAttestation = PublicKeyCredential & { response: AuthenticatorAttestationResponse };

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

  const date = new Date().toISOString();

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
        displayName: `Giano Credential (${date})`,
        name: `giano-${date}`,
      },
      challenge,
    },
  })) as PublicKeyAttestation | null;
};

function normalizeSignatureCoordinate(bytes: Uint8Array, componentLength = 32) {
  let normalizedBytes;
  if (bytes.length < componentLength) {
    normalizedBytes = new Uint8Array(componentLength);
    normalizedBytes.set(bytes, componentLength - bytes.length);
  } else if (bytes.length === componentLength) {
    normalizedBytes = bytes;
  } else if (bytes.length === componentLength + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80) {
    normalizedBytes = bytes.subarray(1);
  } else {
    throw new Error(`Invalid signature component length ${bytes.length}, expected ${componentLength}`);
  }
  return normalizedBytes;
}

// P-256 (secp256r1) subgroup order
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N / 2n;

function encodeSignature(assertionResponse: PublicKeyAssertion['response']) {
  const decodedClientDataJson = new TextDecoder().decode(assertionResponse.clientDataJSON);
  const responseTypeLocation = decodedClientDataJson.indexOf('"type":');
  const challengeLocation = decodedClientDataJson.indexOf('"challenge":');
  const parsedSignature = AsnParser.parse(assertionResponse.signature, ECDSASigValue);
  const { r, s } = parsedSignature;

  const [normalizedR, normalizedS] = [normalizeSignatureCoordinate(new Uint8Array(r)), normalizeSignatureCoordinate(new Uint8Array(s))];

  const numericS = bytesToBigint(normalizedS);

  // Normalize s to the lower value to prevent signature malleability
  const nonMalleableS = toHex(numericS > HALF_N ? N - numericS : numericS, { size: 32 });

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

export type CreateGianoProviderParams = {
  initialChainId: number;
  chains: readonly Chain[];
  transports: Record<number, Transport> | undefined;
  sendTransaction: (s: SendTransactionFnParams) => Promise<Hash>;
};

const factoryContract = Object.freeze({
  address: FACTORY_ADDRESS,
  abi: singleKeyAccountFactoryAbi,
});

export const createGianoProvider = ({ transports, chains, initialChainId, sendTransaction }: CreateGianoProviderParams) => {
  let connectedCredential: PublicKeyCredential | null = null;
  let account: string | null = null;
  let chain: Chain | undefined;
  let transport: Transport | undefined;
  let client: PublicClient | undefined;

  const methods: Record<string, (params?: any) => any> = {
    eth_accounts: async () => {
      return account ? ([account] as `0x${string}`[]) : [];
    },
    eth_chainId: async () => {
      console.log({ chain });
      return `0x${chain!.id.toString(16)}`;
    },
    wallet_addEthereumChain: () => {
      //TODO: implement
    },
    wallet_switchEthereumChain: (params) => {
      const [{ chainId: chainIdHex }] = params;
      const chainId = parseInt(chainIdHex, 16);
      if (chainId === chain?.id) {
        return;
      }
      const newChain = chains.find((chain) => chain.id === chainId);
      if (!newChain) {
        throw new Error(`Unknown chain: ${chainId}`);
      }
      const newTransport = transports?.[newChain.id];
      if (!newTransport) {
        throw new Error('No transport for chain');
      }
      account = null;
      chain = newChain;
      transport = newTransport;
      client = createPublicClient({ transport, chain });
    },
    eth_requestAccounts: async () => {
      if (account) {
        return { accounts: [account], chainId: `0x${chain!.id.toString(16)}` };
      }
      try {
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
          account = await readContract(client!, {
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
            transport: transport!,
            chain: chain!,
            request: {
              to: factoryContract.address,
              data,
            },
          });
          await waitForTransactionReceipt(client!, { hash });
        }
        connectedCredential = credential;
        if (!account) {
          const user = await readContract(client!, {
            ...factoryContract,
            functionName: 'getUser',
            args: [toHex(new Uint8Array(credential.rawId))],
          });
          if (user.account === zeroAddress) {
            throw new Error('User not found');
          }
          account = user.account;
        }
        return [account] as `0x${string}`[];
      } catch (e) {
        console.error('connect error', e);
        throw e;
      }
    },
    eth_call: async (args) => {
      console.log('-> eth_call:', args);
      console.log({ args });
      const [params, block] = args;
      console.log({ account });
      if (account) {
        const call = {
          target: params.to,
          data: params.data,
          expiresAt: maxUint256,
        };
        console.log({ call });
        const challenge = await readContract(client!, {
          address: account as Address,
          abi: singleKeyAccountAbi,
          functionName: 'getStaticChallenge',
          args: [call],
        });
        const credential = await getCredential({ id: connectedCredential!.rawId, challenge: new Uint8Array(toBytes(challenge)) });
        if (!credential) {
          throw new Error('Could not obtain signature for eth_call');
        }
        const signature = encodeSignature(credential.response);
        const readResponse = await readContract(client!, {
          address: account as Address,
          abi: singleKeyAccountAbi,
          functionName: 'staticCall',
          args: [{ call, signature }],
          blockTag: block,
        });
        console.log({ readResponse });
        return readResponse;
      } else {
        const response = await client!.request({ method: 'eth_call', params: args });
        console.log('<- eth_call:', response);
        return response;
      }
    },
    eth_sendTransaction: async ([{ to, data, value }]: any) => {
      try {
        const call = {
          target: to,
          data,
          value: value || 0,
        };
        const challenge = await readContract(client!, {
          address: account as Address,
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
          throw new Error('Error signing challenge!');
        }
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
        const hash = await sendTransaction({
          chain: chain!,
          transport: transport!,
          request: {
            to: account as Address,
            data: gianoExecuteData,
          },
        });
        return hash;
      } catch (e) {
        console.error('request error', e);
        throw e;
      }
    },
  };

  methods.wallet_switchEthereumChain([{ chainId: initialChainId.toString(16) }]);

  const provider: EIP1193Provider = {
    request: async (args: EIP1193Parameters) => {
      const { method, params } = args;
      if (!(method in methods)) {
        return client!.request({ ...args } as any);
      }
      const response = await methods[method](params);
      console.log({ response });
      return response;
    },
    on: (event, listener) => {
      console.log('on event', event);
      return provider;
    },
    removeListener: (event, listener) => {
      console.log('remove listener', event);
      return provider;
    },
  };

  return provider;
};
