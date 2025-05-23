import { gianoSmartWalletAbi, gianoSmartWalletFactoryAbi } from '@appliedblockchain/giano-contracts';
import * as Signature from 'ox/Signature';
import type * as WebAuthnP256 from 'ox/WebAuthnP256';
import type { Address, Assign, Hash, Hex, LocalAccount, OneOf, Prettify, TypedData, TypedDataDefinition } from 'viem';
import {
  BaseError,
  decodeFunctionData,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  hashMessage,
  hashTypedData,
  pad,
  parseSignature,
  size,
  stringToHex,
} from 'viem';
import type { SmartAccount, SmartAccountImplementation, UserOperation, WebAuthnAccount } from 'viem/account-abstraction';
import { entryPoint08Abi, entryPoint08Address, getUserOperationHash, toSmartAccount } from 'viem/account-abstraction';
import { readContract } from 'viem/actions';

export type ToGianoSmartAccountParameters = {
  address?: Address | undefined;
  client: GianoSmartAccountImplementation['client'];
  ownerIndex?: number | undefined;
  owners: readonly (Address | OneOf<LocalAccount | WebAuthnAccount>)[];
  nonce?: bigint | undefined;
};

export type ToGianoSmartAccountReturnType = Prettify<SmartAccount<GianoSmartAccountImplementation>>;

export type GianoSmartAccountImplementation = Assign<
  SmartAccountImplementation<typeof entryPoint08Abi, '0.8', { abi: typeof abi; factory: { abi: typeof factoryAbi; address: Address } }>,
  {
    decodeCalls: NonNullable<SmartAccountImplementation['decodeCalls']>;
    sign: NonNullable<SmartAccountImplementation['sign']>;
  }
>;

/**
 * @description Create a Giano Smart Account.
 *
 * @param parameters - {@link ToGianoSmartAccountParameters}
 * @returns Giano Smart Account. {@link ToGianoSmartAccountReturnType}
 *
 * @example
 * import { toGianoSmartAccount } from 'viem/account-abstraction'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { client } from './client.js'
 *
 * const account = toGianoSmartAccount({
 *   client,
 *   owners: [privateKeyToAccount('0x...')],
 * })
 */
export async function toGianoSmartAccount(parameters: ToGianoSmartAccountParameters): Promise<ToGianoSmartAccountReturnType> {
  const { client, ownerIndex = 0, owners, nonce = 0n } = parameters;

  let address = parameters.address;

  const entryPoint = {
    abi: entryPoint08Abi,
    address: entryPoint08Address,
    version: '0.8',
  } as const;
  const factory = {
    abi: factoryAbi,
    address: '0x7C8BcFd7Ef2165Ec5aEfBA81b152d2Be54Eb02F2',
  } as const;

  const owners_bytes = owners.map((owner) => {
    if (typeof owner === 'string') return pad(owner);
    if (owner.type === 'webAuthn') return owner.publicKey;
    if (owner.type === 'local') return pad(owner.address);
    throw new BaseError('invalid owner type');
  });

  const owner = (() => {
    const owner = owners[ownerIndex] ?? owners[0];
    if (typeof owner === 'string') return { address: owner, type: 'address' } as const;
    return owner;
  })();

  return toSmartAccount({
    client,
    entryPoint,

    extend: { abi, factory },

    async decodeCalls(data) {
      const result = decodeFunctionData({
        abi,
        data,
      });

      if (result.functionName === 'execute') return [{ to: result.args[0], value: result.args[1], data: result.args[2] }];
      if (result.functionName === 'executeBatch')
        return result.args[0].map((arg) => ({
          to: arg.target,
          value: arg.value,
          data: arg.data,
        }));
      throw new BaseError(`unable to decode calls for "${result.functionName}"`);
    },

    async encodeCalls(calls) {
      if (calls.length === 1)
        return encodeFunctionData({
          abi,
          functionName: 'execute',
          args: [calls[0].to, calls[0].value ?? 0n, calls[0].data ?? '0x'],
        });
      return encodeFunctionData({
        abi,
        functionName: 'executeBatch',
        args: [
          calls.map((call) => ({
            data: call.data ?? '0x',
            target: call.to,
            value: call.value ?? 0n,
          })),
        ],
      });
    },

    async getAddress() {
      address ??= await readContract(client, {
        ...factory,
        functionName: 'getAddress',
        args: [owners_bytes, nonce],
      });
      return address;
    },

    async getFactoryArgs() {
      const factoryData = encodeFunctionData({
        abi: factory.abi,
        functionName: 'createAccount',
        args: [owners_bytes, nonce],
      });
      return { factory: factory.address, factoryData };
    },

    async getStubSignature() {
      if (owner.type === 'webAuthn')
        return '0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001949fc7c88032b9fcb5f6efc7a7b8c63668eae9871b765e23123bb473ff57aa831a7c0d9276168ebcc29f2875a0239cffdf2a9cd1c2007c5c77c071db9264df1d000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273496a396e6164474850596759334b7156384f7a4a666c726275504b474f716d59576f4d57516869467773222c226f726967696e223a2268747470733a2f2f7369676e2e636f696e626173652e636f6d222c2263726f73734f726967696e223a66616c73657d00000000000000000000000000000000000000000000';
      return wrapSignature({
        ownerIndex,
        signature: '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c',
      });
    },

    async sign(parameters) {
      const address = await this.getAddress();

      const typedData = toReplaySafeTypedData({
        address,
        chainId: client.chain!.id,
        hash: parameters.hash,
      });

      if (owner.type === 'address') throw new Error('owner cannot sign');
      const signature = await signTypedData({ owner, typedData });

      return wrapSignature({
        ownerIndex,
        signature,
      });
    },

    async signMessage(parameters) {
      const { message } = parameters;
      const address = await this.getAddress();

      const typedData = toReplaySafeTypedData({
        address,
        chainId: client.chain!.id,
        hash: hashMessage(message),
      });

      if (owner.type === 'address') throw new Error('owner cannot sign');
      const signature = await signTypedData({ owner, typedData });

      return wrapSignature({
        ownerIndex,
        signature,
      });
    },

    async signTypedData(parameters) {
      const { domain, types, primaryType, message } = parameters as TypedDataDefinition<TypedData, string>;
      const address = await this.getAddress();

      const typedData = toReplaySafeTypedData({
        address,
        chainId: client.chain!.id,
        hash: hashTypedData({
          domain,
          message,
          primaryType,
          types,
        }),
      });

      if (owner.type === 'address') throw new Error('owner cannot sign');
      const signature = await signTypedData({ owner, typedData });

      return wrapSignature({
        ownerIndex,
        signature,
      });
    },

    async signUserOperation(parameters) {
      const { chainId = client.chain!.id, ...userOperation } = parameters;

      const address = await this.getAddress();
      const hash = getUserOperationHash({
        chainId,
        entryPointAddress: entryPoint.address,
        entryPointVersion: entryPoint.version,
        userOperation: {
          ...(userOperation as unknown as UserOperation),
          sender: address,
        },
      });

      if (owner.type === 'address') throw new Error('owner cannot sign');
      const signature = await sign({ hash, owner });

      return wrapSignature({
        ownerIndex,
        signature,
      });
    },

    userOperation: {
      async estimateGas(userOperation) {
        if (owner.type !== 'webAuthn') return;

        // Accounts with WebAuthn owner require a minimum verification gas limit of 800,000.
        return {
          verificationGasLimit: BigInt(Math.max(Number(userOperation.verificationGasLimit ?? 0n), 800_000)),
        };
      },
    },
  });
}

/////////////////////////////////////////////////////////////////////////////////////////////
// Utilities
/////////////////////////////////////////////////////////////////////////////////////////////

/** @internal */
export async function signTypedData({ typedData, owner }: { typedData: TypedDataDefinition; owner: OneOf<LocalAccount | WebAuthnAccount> }) {
  if (owner.type === 'local' && owner.signTypedData) return owner.signTypedData(typedData);

  const hash = hashTypedData(typedData);
  return sign({ hash, owner });
}

/** @internal */
export async function sign({ hash, owner }: { hash: Hash; owner: OneOf<LocalAccount | WebAuthnAccount> }) {
  // WebAuthn Account (Passkey)
  if (owner.type === 'webAuthn') {
    const { signature, webauthn } = await owner.sign({
      hash,
    });
    return toWebAuthnSignature({ signature, webauthn });
  }

  if (owner.sign) return owner.sign({ hash });

  throw new BaseError('`owner` does not support raw sign.');
}

/** @internal */
export function toReplaySafeTypedData({ address, chainId, hash }: { address: Address; chainId: number; hash: Hash }) {
  return {
    domain: {
      chainId,
      name: 'Giano Smart Wallet',
      verifyingContract: address,
      version: '1',
    },
    types: {
      GianoSmartWalletMessage: [
        {
          name: 'hash',
          type: 'bytes32',
        },
      ],
    },
    primaryType: 'GianoSmartWalletMessage',
    message: {
      hash,
    },
  } as const;
}

/** @internal */
export function toWebAuthnSignature({ webauthn, signature }: { webauthn: WebAuthnP256.SignMetadata; signature: Hex }) {
  const { r, s } = Signature.fromHex(signature);
  return encodeAbiParameters(
    [
      {
        components: [
          {
            name: 'authenticatorData',
            type: 'bytes',
          },
          { name: 'clientDataJSON', type: 'bytes' },
          { name: 'challengeIndex', type: 'uint256' },
          { name: 'typeIndex', type: 'uint256' },
          {
            name: 'r',
            type: 'uint256',
          },
          {
            name: 's',
            type: 'uint256',
          },
        ],
        type: 'tuple',
      },
    ],
    [
      {
        authenticatorData: webauthn.authenticatorData,
        clientDataJSON: stringToHex(webauthn.clientDataJSON),
        challengeIndex: BigInt(webauthn.challengeIndex),
        typeIndex: BigInt(webauthn.typeIndex),
        r,
        s,
      },
    ],
  );
}

/** @internal */
export function wrapSignature(parameters: { ownerIndex?: number | undefined; signature: Hex }) {
  const { ownerIndex = 0 } = parameters;
  const signatureData = (() => {
    if (size(parameters.signature) !== 65) return parameters.signature;
    const signature = parseSignature(parameters.signature);
    return encodePacked(['bytes32', 'bytes32', 'uint8'], [signature.r, signature.s, signature.yParity === 0 ? 27 : 28]);
  })();
  return encodeAbiParameters(
    [
      {
        components: [
          {
            name: 'ownerIndex',
            type: 'uint8',
          },
          {
            name: 'signatureData',
            type: 'bytes',
          },
        ],
        type: 'tuple',
      },
    ],
    [
      {
        ownerIndex,
        signatureData,
      },
    ],
  );
}

/////////////////////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////////////////////

const abi = gianoSmartWalletAbi;

const factoryAbi = gianoSmartWalletFactoryAbi;
