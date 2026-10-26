import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { keccak256, parseEther, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { entryPoint07Abi } from 'viem/account-abstraction';
import { anvilAvailable, executeCall, KEYS, rpc, startBundler, startDevnet, type Bundler, type Devnet } from './harness.js';
import { createOps, stubSignature } from './ops.js';

/**
 * The bundler end to end against anvil: the same JSON-RPC calls wallet-api makes, an account
 * deployed by its first operation, sponsorship through a paymaster, and the executor's own
 * economics — it must never pay more for a transaction than the EntryPoint reimburses it.
 */

const executor = privateKeyToAccount(KEYS.executor);
const recipient: Address = '0x000000000000000000000000000000000000dEaD';

describe.skipIf(!anvilAvailable)('bundler against anvil', () => {
  let devnet: Devnet;
  let bundler: Bundler;

  beforeAll(async () => {
    devnet = await startDevnet();
    bundler = await startBundler(devnet);
  });
  afterAll(async () => {
    await bundler?.stop();
    devnet?.stop();
  });

  const ops = () => createOps(devnet, bundler.url);
  const draft = (...args: Parameters<ReturnType<typeof createOps>['draft']>) => ops().draft(...args);
  const prepare = (...args: Parameters<ReturnType<typeof createOps>['prepare']>) => ops().prepare(...args);
  const waitForReceipt = (hash: Hex) => ops().waitForReceipt(hash);

  it('answers the configuration methods locally', async () => {
    expect((await rpc(bundler.url, 'eth_chainId')).result).toBe('0x7a69');
    expect((await rpc(bundler.url, 'eth_supportedEntryPoints')).result).toEqual([devnet.entryPoint]);
    expect((await rpc(bundler.url, 'pimlico_getUserOperationGasPrice')).error?.code).toBe(-32601);
  });

  it('deploys a self-funded account with its first operation, and the executor is reimbursed', async () => {
    const salt = 1n;
    const { op: drafted } = { op: await draft(salt, '0x', false) };
    await devnet.test.setBalance({ address: drafted.sender as Address, value: parseEther('1') });

    const { op, hash } = await prepare(salt, executeCall(recipient, parseEther('0.01')));
    const before = await devnet.client.getBalance({ address: executor.address });
    const sent = await rpc(bundler.url, 'eth_sendUserOperation', [op, devnet.entryPoint]);
    expect(sent).toMatchObject({ result: hash });

    const receipt = await waitForReceipt(hash);
    expect(receipt).toMatchObject({
      userOpHash: hash,
      sender: op.sender,
      nonce: '0x0',
      success: true,
      receipt: { status: '0x1', from: executor.address.toLowerCase(), to: devnet.entryPoint.toLowerCase() },
    });
    expect(receipt).not.toHaveProperty('paymaster');
    expect(receipt.logs.length).toBeGreaterThan(0);
    expect(await devnet.client.getBalance({ address: recipient })).toBeGreaterThanOrEqual(parseEther('0.01'));

    const after = await devnet.client.getBalance({ address: executor.address });
    expect(after).toBeGreaterThanOrEqual(before);

    const byHash = await rpc(bundler.url, 'eth_getUserOperationByHash', [hash]);
    expect(byHash.result).toMatchObject({
      entryPoint: devnet.entryPoint,
      transactionHash: receipt.receipt.transactionHash,
      userOperation: { sender: op.sender, nonce: '0x0', factory: devnet.factory, signature: op.signature },
    });
  });

  it('submits a sponsored operation for an account with no balance at all', async () => {
    const { op, hash } = await prepare(2n, executeCall(recipient, 0n), true);
    expect(await devnet.client.getBalance({ address: op.sender as Address })).toBe(0n);
    const deposit = await devnet.client.readContract({ address: devnet.entryPoint, abi: entryPoint07Abi, functionName: 'balanceOf', args: [devnet.paymaster] });
    const before = await devnet.client.getBalance({ address: executor.address });

    expect((await rpc(bundler.url, 'eth_sendUserOperation', [op, devnet.entryPoint])).result).toBe(hash);
    const receipt = await waitForReceipt(hash);
    expect(receipt).toMatchObject({ success: true, paymaster: devnet.paymaster });

    const charged = deposit - (await devnet.client.readContract({ address: devnet.entryPoint, abi: entryPoint07Abi, functionName: 'balanceOf', args: [devnet.paymaster] }));
    expect(charged).toBe(BigInt(receipt.actualGasCost));
    expect(await devnet.client.getBalance({ address: executor.address })).toBeGreaterThanOrEqual(before);
  });

  it('reports a call that would revert during estimation, with its reason', async () => {
    // A transfer of more than the account holds reverts inside execute().
    const op = await draft(1n, executeCall(recipient, parseEther('1000')), false);
    const estimate = await rpc(bundler.url, 'eth_estimateUserOperationGas', [op, devnet.entryPoint]);
    expect(estimate.error?.code).toBe(-32521);
    expect(estimate.error?.message).toMatch(/reverted during simulation/);
  });

  it('refuses what the EntryPoint would refuse, with Alto\'s codes', async () => {
    const { op } = await prepare(1n, executeCall(recipient, 1n));

    const badSignature = await rpc(bundler.url, 'eth_sendUserOperation', [{ ...op, signature: stubSignature }, devnet.entryPoint]);
    expect(badSignature.error).toMatchObject({ code: -32507 });
    expect(badSignature.error?.message).toMatch(/AA24/);

    const lowPvg = await rpc(bundler.url, 'eth_sendUserOperation', [{ ...op, preVerificationGas: '0x5208' }, devnet.entryPoint]);
    expect(lowPvg.error).toMatchObject({ code: -32500 });
    expect(lowPvg.error?.message).toMatch(/preVerificationGas is not enough/);

    const cheap = await rpc(bundler.url, 'eth_sendUserOperation', [{ ...op, maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x1' }, devnet.entryPoint]);
    expect(cheap.error).toMatchObject({ code: -32602 });
    expect(cheap.error?.message).toMatch(/maxFeePerGas must be at least/);

    const otherEntryPoint = await rpc(bundler.url, 'eth_sendUserOperation', [op, recipient]);
    expect(otherEntryPoint.error).toMatchObject({ code: -32602 });

    const sent = await rpc(bundler.url, 'eth_sendUserOperation', [op, devnet.entryPoint]);
    await waitForReceipt(sent.result);
    // The same nonce again, now used.
    const { op: replay } = { op: { ...op, callData: executeCall(recipient, 2n) } };
    const reused = await rpc(bundler.url, 'eth_sendUserOperation', [replay, devnet.entryPoint]);
    expect(reused.error?.message).toMatch(/AA2[45]/);
  });

  it('is idempotent for an operation it already has', async () => {
    const { op, hash } = await prepare(1n, executeCall(recipient, 3n));
    const [first, second] = await Promise.all([
      rpc(bundler.url, 'eth_sendUserOperation', [op, devnet.entryPoint]),
      rpc(bundler.url, 'eth_sendUserOperation', [op, devnet.entryPoint]),
    ]);
    expect(first.result).toBe(hash);
    expect(second.result).toBe(hash);
    await waitForReceipt(hash);
    expect(bundler.submitter.get(hash)?.transactions).toHaveLength(1);
  });

  it('answers null for an operation it has never seen', async () => {
    const unknown = keccak256('0x1234');
    expect((await rpc(bundler.url, 'eth_getUserOperationReceipt', [unknown])).result).toBeNull();
    expect((await rpc(bundler.url, 'eth_getUserOperationByHash', [unknown])).result).toBeNull();
  });

  it('finds a receipt from the chain after a restart', async () => {
    const { op, hash } = await prepare(1n, executeCall(recipient, 4n));
    await rpc(bundler.url, 'eth_sendUserOperation', [op, devnet.entryPoint]);
    const receipt = await waitForReceipt(hash);

    const restarted = await startBundler(devnet);
    try {
      expect(restarted.submitter.get(hash)).toBeUndefined();
      expect((await rpc(restarted.url, 'eth_getUserOperationReceipt', [hash])).result).toEqual(receipt);
      expect((await rpc(restarted.url, 'eth_getUserOperationByHash', [hash])).result).toMatchObject({ transactionHash: receipt.receipt.transactionHash });
    } finally {
      await restarted.stop();
    }
  });

  describe('a transaction that is not mined', () => {
    let slow: Bundler;
    beforeAll(async () => {
      slow = await startBundler(devnet, { resubmitTimeoutMs: 300, maxReplacements: 1 });
      await devnet.test.setAutomine(false);
    });
    afterAll(async () => {
      await devnet.test.setAutomine(true);
      await slow.stop();
    });

    it('is re-priced, and the replacement is what gets mined', async () => {
      const { op, hash } = await prepare(1n, executeCall(recipient, 5n));
      expect((await rpc(slow.url, 'eth_sendUserOperation', [op, devnet.entryPoint])).result).toBe(hash);
      await until(() => (slow.submitter.get(hash)?.transactions.length ?? 0) >= 2);
      await devnet.test.mine({ blocks: 1 });
      const receipt = await until(async () => (await rpc(slow.url, 'eth_getUserOperationReceipt', [hash])).result);
      expect(receipt.success).toBe(true);
      expect(receipt.receipt.transactionHash).toBe(slow.submitter.get(hash)?.transactions[1]);
    });

    it('is cancelled once re-pricing is exhausted, which frees the executor nonce', async () => {
      const { op, hash } = await prepare(1n, executeCall(recipient, 6n));
      await rpc(slow.url, 'eth_sendUserOperation', [op, devnet.entryPoint]);
      await until(() => slow.submitter.get(hash)?.status === 'failed');
      await devnet.test.mine({ blocks: 1 });
      const nonce = await devnet.client.getTransactionCount({ address: executor.address, blockTag: 'latest' });
      expect(await devnet.client.getTransactionCount({ address: executor.address, blockTag: 'pending' })).toBe(nonce);
      expect((await rpc(slow.url, 'eth_getUserOperationReceipt', [hash])).result).toBeNull();
    });
  });
});

async function until<T>(probe: () => T | Promise<T>, timeoutMs = 10_000): Promise<NonNullable<T>> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await probe();
    if (value) return value as NonNullable<T>;
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}
