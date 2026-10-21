import { expect } from 'vitest';
import { concat, encodeAbiParameters, encodeFunctionData, keccak256, toHex, type Address, type Hex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { entryPoint07Abi, getUserOperationHash, toPackedUserOperation } from 'viem/account-abstraction';
import { KEYS, rpc, simpleAccountFactoryAbi, verifyingPaymasterAbi, type Devnet } from './harness.js';

/** Builds, estimates and signs SimpleAccount operations on one devnet, through one bundler endpoint. */

const owner = privateKeyToAccount(KEYS.owner);
const sponsor = privateKeyToAccount(KEYS.sponsor);

/** A well-formed signature from an unrelated key: recovers, but to the wrong owner. */
export const stubSignature = await privateKeyToAccount(generatePrivateKey()).signMessage({ message: { raw: keccak256('0x01') } });

export type RpcOp = Record<string, Hex>;

export function createOps(devnet: Devnet, url: string) {
  const hex = (value: bigint) => toHex(value);

  async function draft(salt: bigint, callData: Hex, sponsored: boolean): Promise<RpcOp> {
    const { client, factory, entryPoint, paymaster } = devnet;
    const sender = (await client.readContract({ address: factory, abi: simpleAccountFactoryAbi, functionName: 'getAddress', args: [owner.address, salt] })) as Address;
    const code = await client.getCode({ address: sender });
    const nonce = await client.readContract({ address: entryPoint, abi: entryPoint07Abi, functionName: 'getNonce', args: [sender, 0n] });
    const fees = await client.estimateFeesPerGas();
    const op: RpcOp = {
      sender,
      nonce: hex(nonce),
      callData,
      maxFeePerGas: hex(fees.maxFeePerGas),
      maxPriorityFeePerGas: hex(fees.maxPriorityFeePerGas),
      signature: stubSignature,
    };
    if (!code || code === '0x') {
      op.factory = factory;
      op.factoryData = encodeFunctionData({ abi: simpleAccountFactoryAbi, functionName: 'createAccount', args: [owner.address, salt] });
    }
    if (sponsored) {
      op.paymaster = paymaster;
      op.paymasterData = concat([encodeAbiParameters([{ type: 'uint48' }, { type: 'uint48' }], [0, 0]), stubSignature]);
    }
    return op;
  }

  const toOp = (op: RpcOp) => ({
    sender: op.sender as Address,
    nonce: BigInt(op.nonce),
    callData: op.callData,
    callGasLimit: BigInt(op.callGasLimit),
    verificationGasLimit: BigInt(op.verificationGasLimit),
    preVerificationGas: BigInt(op.preVerificationGas),
    maxFeePerGas: BigInt(op.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas),
    signature: op.signature,
    ...(op.factory ? { factory: op.factory as Address, factoryData: op.factoryData } : {}),
    ...(op.paymaster
      ? {
          paymaster: op.paymaster as Address,
          paymasterData: op.paymasterData,
          paymasterVerificationGasLimit: BigInt(op.paymasterVerificationGasLimit),
          paymasterPostOpGasLimit: BigInt(op.paymasterPostOpGasLimit),
        }
      : {}),
  });

  /** Estimate, then sign as a wallet would: paymaster authorisation first, then the owner over the final hash. */
  async function prepare(salt: bigint, callData: Hex, sponsored = false): Promise<{ op: RpcOp; hash: Hex }> {
    const op = await draft(salt, callData, sponsored);
    const estimate = await rpc<Record<string, Hex>>(url, 'eth_estimateUserOperationGas', [op, devnet.entryPoint]);
    expect(estimate.error).toBeUndefined();
    Object.assign(op, {
      preVerificationGas: estimate.result!.preVerificationGas,
      verificationGasLimit: estimate.result!.verificationGasLimit,
      callGasLimit: estimate.result!.callGasLimit,
      ...(sponsored
        ? {
            paymasterVerificationGasLimit: estimate.result!.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: estimate.result!.paymasterPostOpGasLimit,
          }
        : {}),
    });
    if (sponsored) {
      const validUntil = Math.floor(Date.now() / 1000) + 3600;
      const sponsorHash = (await devnet.client.readContract({
        address: devnet.paymaster,
        abi: verifyingPaymasterAbi,
        functionName: 'getHash',
        args: [toPackedUserOperation(toOp(op) as never), validUntil, 0],
      })) as Hex;
      op.paymasterData = concat([
        encodeAbiParameters([{ type: 'uint48' }, { type: 'uint48' }], [validUntil, 0]),
        await sponsor.signMessage({ message: { raw: sponsorHash } }),
      ]);
    }
    const hash = getUserOperationHash({ chainId: devnet.chainId, entryPointAddress: devnet.entryPoint, entryPointVersion: '0.7', userOperation: toOp(op) as never });
    op.signature = await owner.signMessage({ message: { raw: hash } });
    return { op, hash };
  }

  async function waitForReceipt(hash: Hex) {
    for (let i = 0; i < 200; i++) {
      const { result } = await rpc(url, 'eth_getUserOperationReceipt', [hash]);
      if (result) return result;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`no receipt for ${hash}`);
  }

  return { draft, toOp, prepare, waitForReceipt };
}
