import {
  decodeFunctionData,
  getAddress,
  hexToBigInt,
  numberToHex,
  sliceHex,
  size,
  type Address,
  type Hex,
  type PublicClient,
  type RpcLog,
  type RpcTransaction,
  type RpcTransactionReceipt,
} from 'viem';
import { entryPoint07Abi } from 'viem/account-abstraction';
import type { Submitter } from './submitter.js';
import { formatUserOp, userOpHash, type UserOp } from './userop.js';

/**
 * eth_getUserOperationReceipt and eth_getUserOperationByHash, in the shapes Alto returned. Both
 * answer from the chain, so they survive a restart: an operation this process submitted is found
 * through its transaction, any other through its UserOperationEvent in the last
 * `maxBlockRange` blocks. A pending operation answers null, as it did with Alto.
 */

const USER_OPERATION_EVENT = '0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f';
const USER_OPERATION_REVERT_REASON = '0x1c4fada7374c0a9ee8841fc38afe82932dc0f8e69012e927f061a8bae611a201';

export type Lookup = ReturnType<typeof createLookup>;

export function createLookup(options: {
  client: PublicClient;
  chainId: number;
  entryPoint: Address;
  maxBlockRange: bigint;
  submitter: Submitter;
}) {
  const { client, chainId, entryPoint, maxBlockRange, submitter } = options;

  const request = <T>(method: string, params: unknown[]) => client.request({ method, params } as never) as Promise<T>;

  /** The transaction that included the operation, if it has been mined. */
  const findTransaction = async (hash: Hex): Promise<Hex | null> => {
    const known = submitter.get(hash);
    if (known) return known.status === 'included' ? (known.transactionHash ?? null) : null;
    const latest = await client.getBlockNumber();
    const fromBlock = latest > maxBlockRange ? latest - maxBlockRange : 0n;
    const logs = await request<RpcLog[]>('eth_getLogs', [
      { address: entryPoint, topics: [USER_OPERATION_EVENT, hash], fromBlock: numberToHex(fromBlock), toBlock: 'latest' },
    ]);
    const found = logs.find((log) => !log.removed && log.transactionHash);
    return found?.transactionHash ?? null;
  };

  const isEntryPointEvent = (log: RpcLog, topic: Hex) => log.address.toLowerCase() === entryPoint.toLowerCase() && log.topics[0] === topic;

  return {
    async receipt(hash: Hex) {
      const transactionHash = await findTransaction(hash);
      if (!transactionHash) return null;
      const receipt = await request<RpcTransactionReceipt | null>('eth_getTransactionReceipt', [transactionHash]);
      if (!receipt) return null;

      const index = receipt.logs.findIndex(
        (log) => isEntryPointEvent(log, USER_OPERATION_EVENT) && log.topics[1]?.toLowerCase() === hash.toLowerCase(),
      );
      if (index < 0) return null;
      const event = receipt.logs[index];
      // The operation's own logs: everything after the previous operation's event, up to its own.
      let start = index - 1;
      while (start >= 0 && !isEntryPointEvent(receipt.logs[start], USER_OPERATION_EVENT)) start--;
      const ownLogs = receipt.logs.slice(start + 1, index);

      // UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster,
      //                    uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)
      const word = (n: number) => sliceHex(event.data, n * 32, n * 32 + 32);
      const paymaster = getAddress(sliceHex(event.topics[3]!, 12));
      const revert = ownLogs.find(
        (log) => isEntryPointEvent(log, USER_OPERATION_REVERT_REASON) && log.topics[1]?.toLowerCase() === hash.toLowerCase(),
      );

      return {
        userOpHash: hash,
        entryPoint: event.address,
        sender: getAddress(sliceHex(event.topics[2]!, 12)),
        nonce: numberToHex(hexToBigInt(word(0))),
        ...(paymaster === '0x0000000000000000000000000000000000000000' ? {} : { paymaster }),
        actualGasUsed: numberToHex(hexToBigInt(word(3))),
        actualGasCost: numberToHex(hexToBigInt(word(2))),
        success: hexToBigInt(word(1)) === 1n,
        ...(revert ? { reason: revertReasonOf(revert) } : {}),
        logs: ownLogs.map(formatLog),
        receipt: {
          transactionHash: receipt.transactionHash,
          transactionIndex: receipt.transactionIndex,
          blockHash: receipt.blockHash,
          blockNumber: receipt.blockNumber,
          from: receipt.from,
          to: receipt.to,
          cumulativeGasUsed: receipt.cumulativeGasUsed,
          gasUsed: receipt.gasUsed,
          contractAddress: null,
          logs: receipt.logs.map(formatLog),
          logsBloom: receipt.logsBloom,
          status: receipt.status,
          effectiveGasPrice: receipt.effectiveGasPrice,
        },
      };
    },

    async byHash(hash: Hex) {
      const transactionHash = await findTransaction(hash);
      if (!transactionHash) return null;
      const transaction = await request<RpcTransaction | null>('eth_getTransactionByHash', [transactionHash]);
      if (!transaction?.blockHash || !transaction.to) return null;
      const { functionName, args } = decodeFunctionData({ abi: entryPoint07Abi, data: transaction.input });
      if (functionName !== 'handleOps') return null;
      const op = args[0].map(unpack).find((candidate) => userOpHash(candidate, entryPoint, chainId).toLowerCase() === hash.toLowerCase());
      if (!op) return null;
      return {
        userOperation: formatUserOp(op),
        entryPoint: getAddress(transaction.to),
        transactionHash,
        blockHash: transaction.blockHash,
        blockNumber: transaction.blockNumber,
      };
    },
  };
}

function formatLog(log: RpcLog) {
  return {
    logIndex: log.logIndex,
    transactionIndex: log.transactionIndex,
    transactionHash: log.transactionHash,
    blockHash: log.blockHash,
    blockNumber: log.blockNumber,
    address: getAddress(log.address),
    data: log.data,
    topics: log.topics,
  };
}

/** UserOperationRevertReason(bytes32 indexed, address indexed, uint256 nonce, bytes revertReason): the bytes. */
function revertReasonOf(log: RpcLog): Hex {
  const offset = Number(hexToBigInt(sliceHex(log.data, 32, 64)));
  const length = Number(hexToBigInt(sliceHex(log.data, offset, offset + 32)));
  return length === 0 ? '0x' : sliceHex(log.data, offset + 32, offset + 32 + length);
}

type Packed = {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterAndData: Hex;
  signature: Hex;
};

/** PackedUserOperation back to its v0.7 fields. */
export function unpack(packed: Packed): UserOp {
  const high = (word: Hex) => hexToBigInt(sliceHex(word, 0, 16));
  const low = (word: Hex) => hexToBigInt(sliceHex(word, 16, 32));
  const op: UserOp = {
    sender: getAddress(packed.sender),
    nonce: packed.nonce,
    callData: packed.callData,
    verificationGasLimit: high(packed.accountGasLimits),
    callGasLimit: low(packed.accountGasLimits),
    preVerificationGas: packed.preVerificationGas,
    maxPriorityFeePerGas: high(packed.gasFees),
    maxFeePerGas: low(packed.gasFees),
    signature: packed.signature,
  };
  if (size(packed.initCode) >= 20) {
    op.factory = getAddress(sliceHex(packed.initCode, 0, 20));
    op.factoryData = size(packed.initCode) > 20 ? sliceHex(packed.initCode, 20) : '0x';
  }
  if (size(packed.paymasterAndData) >= 52) {
    op.paymaster = getAddress(sliceHex(packed.paymasterAndData, 0, 20));
    op.paymasterVerificationGasLimit = hexToBigInt(sliceHex(packed.paymasterAndData, 20, 36));
    op.paymasterPostOpGasLimit = hexToBigInt(sliceHex(packed.paymasterAndData, 36, 52));
    op.paymasterData = size(packed.paymasterAndData) > 52 ? sliceHex(packed.paymasterAndData, 52) : '0x';
  }
  return op;
}
