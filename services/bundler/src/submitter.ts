import {
  encodeFunctionData,
  keccak256,
  type Address,
  type Hex,
  type PublicClient,
  type RpcTransactionReceipt,
} from 'viem';
import type { PrivateKeyAccount } from 'viem/accounts';
import { entryPoint07Abi } from 'viem/account-abstraction';
import type { Logger } from 'pino';
import { decodeEntryPointRevert, ERROR_CODES, RpcError, validationError } from './errors.js';
import { maxBigInt, scale, staticPreVerificationGas } from './pvg.js';
import type { Metrics } from './metrics.js';
import { nonceKey, nonceSequence, packUserOp, userOpHash, type UserOp } from './userop.js';

/**
 * Submission: one operation, one `handleOps([op], executor)` transaction, sent the moment an
 * executor is free. There is no mempool and no bundling. Each executor key is a lane holding at
 * most one transaction in flight, so its nonce never has a gap; more keys, more lanes.
 *
 * The transaction is priced at the operation's own fees. The EntryPoint reimburses the executor at
 * `min(maxFeePerGas, baseFee + maxPriorityFeePerGas)` of the operation, which is then exactly what
 * the transaction pays per gas, and preVerificationGas covers the gas it does not meter.
 */

export type TrackedStatus = 'queued' | 'submitted' | 'included' | 'failed';

export type Tracked = {
  hash: Hex;
  op: UserOp;
  status: TrackedStatus;
  /** Every transaction broadcast for it, latest last — any one of them may be the one mined. */
  transactions: Hex[];
  /** The mined transaction, once there is one. */
  transactionHash?: Hex;
  error?: string;
  updatedAt: number;
};

export type SubmitterOptions = {
  client: PublicClient;
  chainId: number;
  entryPoint: Address;
  executors: PrivateKeyAccount[];
  resubmitTimeoutMs: number;
  maxReplacements: number;
  pollIntervalMs: number;
  log: Logger;
  metrics: Metrics;
};

/** How long a finished operation stays answerable from memory, before lookups go to the chain. */
const RETAIN_MS = 60 * 60 * 1000;
/** A replacement must outbid the transaction it replaces; nodes require at least 10%. */
const REPLACEMENT_BUMP_PERCENT = 115n;
const SEND_ATTEMPTS = 3;
/** A cancellation is re-priced this many times at most; past that the lane waits, and says so. */
const MAX_CANCEL_BUMPS = 3;

export type Submitter = ReturnType<typeof createSubmitter>;

export function createSubmitter(options: SubmitterOptions) {
  const { client, chainId, entryPoint, executors, log, metrics } = options;
  const chain = String(chainId);
  const tracked = new Map<Hex, Tracked>();
  /** Operations waiting for an earlier nonce of the same sender and key: predecessor → waiting. */
  const successors = new Map<Hex, Hex>();

  // ── executor lanes ──────────────────────────────────────────────────────────────────────
  const idle: PrivateKeyAccount[] = [...executors];
  const waiting: Array<(executor: PrivateKeyAccount) => void> = [];
  const acquire = () =>
    new Promise<PrivateKeyAccount>((resolve) => {
      const executor = idle.shift();
      if (executor) resolve(executor);
      else waiting.push(resolve);
    });
  const release = (executor: PrivateKeyAccount) => {
    const next = waiting.shift();
    if (next) next(executor);
    else idle.push(executor);
  };

  const handleOpsData = (op: UserOp, beneficiary: Address) =>
    encodeFunctionData({ abi: entryPoint07Abi, functionName: 'handleOps', args: [[packUserOp(op)], beneficiary] });

  /**
   * The real EntryPoint, the real state, the executor as sender: if handleOps would revert, so
   * would the transaction, so nothing is sent that this does not pass.
   */
  const simulate = async (op: UserOp, executor: Address): Promise<bigint> => {
    try {
      // `latest`, not the node's default: some nodes (anvil) estimate against the pending block,
      // where our own in-flight transaction has already used the operation's nonce.
      return await client.estimateGas({ account: executor, to: entryPoint, data: handleOpsData(op, executor), blockTag: 'latest' });
    } catch (error) {
      throw validationError(decodeEntryPointRevert(error));
    }
  };

  /** Checks that need no simulation, in the order Alto made them. */
  const precheck = async (op: UserOp) => {
    if (op.verificationGasLimit < 10_000n) throw new RpcError(ERROR_CODES.invalidParams, 'verificationGasLimit must be at least 10000');
    if (op.preVerificationGas === 0n) throw new RpcError(ERROR_CODES.invalidParams, 'user operation gas limits must be larger than 0');
    const required = staticPreVerificationGas(op, 'exact');
    if (op.preVerificationGas < required) {
      throw new RpcError(ERROR_CODES.validationReverted, `preVerificationGas is not enough, required: ${required}, got: ${op.preVerificationGas}`);
    }
    // Sent at the operation's own fees, so an operation priced below the base fee cannot be included.
    const block = await client.getBlock({ blockTag: 'latest' });
    if (block.baseFeePerGas != null && op.maxFeePerGas < block.baseFeePerGas) {
      throw new RpcError(
        ERROR_CODES.invalidParams,
        `maxFeePerGas must be at least ${block.baseFeePerGas} (current maxFeePerGas: ${op.maxFeePerGas})`,
      );
    }
  };

  const finish = (entry: Tracked, status: 'included' | 'failed', detail: { transactionHash?: Hex; error?: string } = {}) => {
    entry.status = status;
    entry.updatedAt = Date.now();
    Object.assign(entry, detail);
    const next = successors.get(entry.hash);
    if (next) {
      successors.delete(entry.hash);
      const successor = tracked.get(next);
      if (successor) void submitQueued(successor);
    }
  };

  /** A queued operation's turn: validated now, against the state its predecessor left. */
  const submitQueued = async (entry: Tracked) => {
    try {
      await submit(entry);
    } catch (error) {
      log.warn({ userOpHash: entry.hash, err: error }, 'queued user operation failed validation and was dropped');
      metrics.userOperations.inc({ chain, outcome: 'dropped' });
      finish(entry, 'failed', { error: (error as Error).message });
    }
  };

  /** Validate on a free lane and broadcast; resolves once the transaction is in the node's mempool. */
  const submit = async (entry: Tracked) => {
    const executor = await acquire();
    let handedOff = false;
    try {
      const gasEstimate = await simulate(entry.op, executor.address);
      const sent = await broadcast(entry, executor, gasEstimate);
      entry.status = 'submitted';
      entry.updatedAt = Date.now();
      metrics.userOperations.inc({ chain, outcome: 'submitted' });
      log.info({ userOpHash: entry.hash, transactionHash: sent.hash, executor: executor.address, nonce: sent.nonce }, 'user operation submitted');
      handedOff = true;
      void watch(entry, executor, sent).finally(() => release(executor));
    } finally {
      if (!handedOff) release(executor);
    }
  };

  type Sent = { hash: Hex; nonce: number; gas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint; legacy: boolean };

  const broadcast = async (entry: Tracked, executor: PrivateKeyAccount, gasEstimate: bigint): Promise<Sent> => {
    const { op } = entry;
    const block = await client.getBlock({ blockTag: 'latest' });
    // EntryPoint v0.7 aborts the whole transaction (AA95) unless 63/64 of the gas left at the
    // inner call covers the execution limits, so the estimate is floored at what that needs.
    const floor =
      ((op.callGasLimit + (op.paymasterPostOpGasLimit ?? 0n) + 10_000n) * 64n) / 63n +
      op.verificationGasLimit +
      (op.paymasterVerificationGasLimit ?? 0n) +
      op.preVerificationGas;
    const gas = maxBigInt(scale(gasEstimate, 110n), floor);
    return send(executor, {
      data: handleOpsData(op, executor.address),
      to: entryPoint,
      gas,
      maxFeePerGas: op.maxFeePerGas,
      maxPriorityFeePerGas: op.maxPriorityFeePerGas,
      legacy: block.baseFeePerGas == null,
      onHash: (hash) => entry.transactions.push(hash),
    });
  };

  const send = async (
    executor: PrivateKeyAccount,
    tx: { to: Address; data: Hex; gas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint; legacy: boolean; nonce?: number; onHash: (hash: Hex) => void; value?: bigint },
  ): Promise<Sent> => {
    let nonce = tx.nonce ?? (await client.getTransactionCount({ address: executor.address, blockTag: 'pending' }));
    for (let attempt = 1; ; attempt++) {
      const serialized = await executor.signTransaction(
        tx.legacy
          ? { chainId, type: 'legacy', to: tx.to, data: tx.data, value: tx.value ?? 0n, gas: tx.gas, nonce, gasPrice: tx.maxFeePerGas }
          : {
              chainId,
              type: 'eip1559',
              to: tx.to,
              data: tx.data,
              value: tx.value ?? 0n,
              gas: tx.gas,
              nonce,
              maxFeePerGas: tx.maxFeePerGas,
              maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
            },
      );
      const hash = keccak256(serialized);
      try {
        await client.request({ method: 'eth_sendRawTransaction', params: [serialized] });
      } catch (error) {
        const message = String((error as Error)?.message ?? error).toLowerCase();
        if (!message.includes('already known')) {
          // Another process using the same key (a rolling deploy) took this nonce: take the next.
          const nonceTaken = message.includes('nonce too low') || message.includes('replacement transaction underpriced');
          if (nonceTaken && tx.nonce === undefined && attempt < SEND_ATTEMPTS) {
            nonce = await client.getTransactionCount({ address: executor.address, blockTag: 'pending' });
            continue;
          }
          throw new RpcError(ERROR_CODES.internal, `the bundler could not send its transaction: ${(error as Error).message}`);
        }
      }
      tx.onHash(hash);
      return { hash, nonce, gas: tx.gas, maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, legacy: tx.legacy };
    }
  };

  const receiptOf = async (hash: Hex): Promise<RpcTransactionReceipt | null> =>
    (await client.request({ method: 'eth_getTransactionReceipt', params: [hash] })) as RpcTransactionReceipt | null;

  /**
   * Holds the lane until the nonce is used: by our transaction (included, or reverted), by one of
   * its re-priced replacements, or by the cancellation sent once those are exhausted.
   */
  const watch = async (entry: Tracked, executor: PrivateKeyAccount, first: Sent) => {
    let latest = first;
    let lastSentAt = Date.now();
    let replacements = 0;
    let cancelled = false;
    let cancelBumps = 0;
    const sentHashes: Hex[] = [first.hash];
    try {
      for (;;) {
        await sleep(options.pollIntervalMs);
        for (const hash of [...sentHashes].reverse()) {
          const receipt = await receiptOf(hash).catch(() => null);
          if (!receipt) continue;
          settle(entry, receipt, hash);
          return;
        }
        const mined = await client.getTransactionCount({ address: executor.address, blockTag: 'latest' }).catch(() => undefined);
        if (mined !== undefined && mined > latest.nonce) {
          // The nonce moved on without any of our transactions: one more look, then it is gone.
          await sleep(options.pollIntervalMs);
          for (const hash of sentHashes) {
            const receipt = await receiptOf(hash).catch(() => null);
            if (receipt) return settle(entry, receipt, hash);
          }
          if (entry.status !== 'failed') {
            metrics.userOperations.inc({ chain, outcome: 'dropped' });
            finish(entry, 'failed', { error: 'the executor nonce was used by another transaction' });
          }
          log.warn({ userOpHash: entry.hash, executor: executor.address, nonce: latest.nonce }, 'executor nonce consumed by a foreign transaction');
          return;
        }
        if (Date.now() - lastSentAt < options.resubmitTimeoutMs) continue;

        const bumped = {
          maxFeePerGas: scale(latest.maxFeePerGas, REPLACEMENT_BUMP_PERCENT) + 1n,
          maxPriorityFeePerGas: scale(latest.maxPriorityFeePerGas, REPLACEMENT_BUMP_PERCENT) + 1n,
        };
        let stillValid = !cancelled && replacements < options.maxReplacements;
        if (stillValid) {
          stillValid = await simulate(entry.op, executor.address).then(
            () => true,
            (error) => {
              log.warn({ userOpHash: entry.hash, err: error }, 'stuck user operation no longer validates; cancelling its transaction');
              return false;
            },
          );
        }
        const onHash = (hash: Hex) => {
          sentHashes.push(hash);
          if (!cancelled) entry.transactions.push(hash);
        };
        try {
          if (stillValid) {
            replacements++;
            latest = await send(executor, {
              to: entryPoint,
              data: handleOpsData(entry.op, executor.address),
              gas: latest.gas,
              legacy: latest.legacy,
              nonce: latest.nonce,
              onHash,
              ...bumped,
            });
            log.warn({ userOpHash: entry.hash, transactionHash: latest.hash, replacements }, 'user operation transaction re-priced');
          } else if (cancelBumps >= MAX_CANCEL_BUMPS) {
            log.error(
              { userOpHash: entry.hash, executor: executor.address, nonce: latest.nonce },
              'executor nonce still stuck after cancelling; the lane waits for it — check the executor balance and the node',
            );
          } else {
            cancelBumps++;
            if (!cancelled) {
              cancelled = true;
              metrics.userOperations.inc({ chain, outcome: 'dropped' });
              finish(entry, 'failed', { error: 'not included in time; the transaction was cancelled' });
            }
            // A zero-value transfer to itself at the same nonce frees the lane; if the original
            // is mined first instead, the receipt check above still finds it.
            latest = await send(executor, {
              to: executor.address,
              data: '0x',
              gas: 21_000n,
              legacy: latest.legacy,
              nonce: latest.nonce,
              onHash,
              ...bumped,
            });
            log.warn({ userOpHash: entry.hash, transactionHash: latest.hash, nonce: latest.nonce }, 'cancelling the stuck executor nonce');
          }
        } catch (error) {
          log.error({ userOpHash: entry.hash, err: error }, 'could not re-price the stuck transaction');
        }
        lastSentAt = Date.now();
      }
    } catch (error) {
      log.error({ userOpHash: entry.hash, err: error }, 'lost track of a submitted user operation');
    } finally {
      void refreshBalance(executor.address);
    }
  };

  const USER_OPERATION_EVENT = '0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f';

  const settle = (entry: Tracked, receipt: RpcTransactionReceipt, hash: Hex) => {
    const event = receipt.logs.find(
      (eventLog) =>
        eventLog.address.toLowerCase() === entryPoint.toLowerCase() &&
        eventLog.topics[0] === USER_OPERATION_EVENT &&
        eventLog.topics[1]?.toLowerCase() === entry.hash.toLowerCase(),
    );
    if (event) {
      metrics.userOperations.inc({ chain, outcome: 'included' });
      log.info({ userOpHash: entry.hash, transactionHash: hash, blockNumber: Number(receipt.blockNumber) }, 'user operation included');
      finish(entry, 'included', { transactionHash: hash });
    } else if (entry.transactions.includes(hash)) {
      // Our handleOps was mined and reverted: the executor paid for it and nobody reimbursed it.
      metrics.userOperations.inc({ chain, outcome: 'reverted' });
      log.error({ userOpHash: entry.hash, transactionHash: hash }, 'handleOps transaction reverted on chain');
      finish(entry, 'failed', { transactionHash: hash, error: 'the handleOps transaction reverted' });
    } else {
      log.info({ userOpHash: entry.hash, transactionHash: hash }, 'executor nonce freed by cancellation');
    }
  };

  const refreshBalance = async (address: Address) => {
    try {
      metrics.executorBalance.set({ chain, executor: address }, Number(await client.getBalance({ address })));
    } catch {
      // the next refresh tries again
    }
  };

  // Finished operations are forgotten after a while; lookups then come from the chain's logs.
  const pruner = setInterval(() => {
    const cutoff = Date.now() - RETAIN_MS;
    for (const [hash, entry] of tracked) {
      if ((entry.status === 'included' || entry.status === 'failed') && entry.updatedAt < cutoff) tracked.delete(hash);
    }
  }, 60_000);
  pruner.unref();

  return {
    executors: executors.map((executor) => executor.address),
    refreshBalances: () => Promise.all(executors.map((executor) => refreshBalance(executor.address))),
    get(hash: Hex): Tracked | undefined {
      return tracked.get(hash.toLowerCase() as Hex);
    },
    pending(): number {
      let count = 0;
      for (const entry of tracked.values()) if (entry.status === 'queued' || entry.status === 'submitted') count++;
      return count;
    },
    stop() {
      clearInterval(pruner);
    },

    /** eth_sendUserOperation: resolves with the operation hash once its transaction is broadcast. */
    async send(op: UserOp): Promise<Hex> {
      const hash = userOpHash(op, entryPoint, chainId).toLowerCase() as Hex;
      const known = tracked.get(hash);
      if (known && known.status !== 'failed') return hash;

      // Same sender and nonce as an operation still in flight (a re-signed copy, say): only one
      // can ever validate, and sending both would revert the second handleOps at the executor's cost.
      const rival = [...tracked.values()].find(
        (other) => (other.status === 'queued' || other.status === 'submitted') && other.op.sender === op.sender && other.op.nonce === op.nonce,
      );
      if (rival) {
        throw new RpcError(
          ERROR_CODES.invalidParams,
          'AA25 invalid account nonce: Another UserOperation with same sender and nonce is already being processed',
        );
      }

      // Tracked before the first await, so a concurrent duplicate is answered by the check above.
      const entry: Tracked = { hash, op, status: 'queued', transactions: [], updatedAt: Date.now() };
      tracked.set(hash, entry);
      try {
        await precheck(op);

        // Same sender, same nonce key, the very next sequence after an operation still in flight:
        // it cannot validate until that one lands, so it waits for it rather than being refused.
        const predecessor = [...tracked.values()].find(
          (other) =>
            other !== entry &&
            (other.status === 'queued' || other.status === 'submitted') &&
            other.op.sender === op.sender &&
            nonceKey(other.op.nonce) === nonceKey(op.nonce) &&
            nonceSequence(other.op.nonce) + 1n === nonceSequence(op.nonce),
        );
        if (predecessor && !successors.has(predecessor.hash)) {
          successors.set(predecessor.hash, hash);
          log.info({ userOpHash: hash, after: predecessor.hash }, 'user operation queued behind its predecessor');
          return hash;
        }

        await submit(entry);
      } catch (error) {
        tracked.delete(hash);
        metrics.userOperations.inc({ chain, outcome: 'rejected' });
        throw error;
      }
      return hash;
    },
  };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
