import { describe, expect, it } from 'vitest';
import { LogRangeUnboundedError } from '../src/errors';
import { isBlockRangeError, scanLogs } from '../src/log-scan';

/** The rejection Base Sepolia's public endpoint returns, as viem wraps it. */
const baseSepoliaRejection = () => {
  const rpc = Object.assign(new Error('eth_getLogs is limited to a 10,000 range'), { code: -32614 });
  return Object.assign(new Error('An internal error was received.'), { shortMessage: 'An internal error was received.', cause: rpc });
};

type Window = { from: bigint; to: bigint };

/** A node serving one log per block, refusing any query wider than `cap`. */
function node(cap: bigint) {
  const seen: Window[] = [];
  let rejected = 0;
  return {
    seen,
    get rejected() {
      return rejected;
    },
    query: async (from: bigint, to: bigint): Promise<readonly bigint[]> => {
      if (to - from + 1n > cap) {
        rejected++;
        throw baseSepoliaRejection();
      }
      seen.push({ from, to });
      const logs: bigint[] = [];
      for (let block = from; block <= to; block++) logs.push(block);
      return logs;
    },
  };
}

describe('isBlockRangeError', () => {
  it('recognises the rejection through viem’s wrapper', () => {
    expect(isBlockRangeError(baseSepoliaRejection())).toBe(true);
  });

  it.each([
    'query returned more than 10000 results',
    'Log response size exceeded. You can make eth_getLogs requests with up to a 2K block range',
    'exceed maximum block range: 5000',
    'requested too many blocks from 0 to 47000000, maximum is set to 1024',
  ])('recognises %s', (message) => {
    expect(isBlockRangeError(new Error(message))).toBe(true);
  });

  it('does not swallow unrelated failures', () => {
    expect(isBlockRangeError(new Error('execution reverted'))).toBe(false);
    expect(isBlockRangeError(new Error('fetch failed'))).toBe(false);
    expect(isBlockRangeError(undefined)).toBe(false);
  });
});

describe('scanLogs', () => {
  const scan = (from: bigint, to: bigint, cap: bigint, maxRange?: bigint) => {
    const rpc = node(cap);
    return { rpc, run: () => scanLogs({ fromBlock: from, toBlock: to, maxRange, subject: 'test logs', query: rpc.query }) };
  };

  it('returns every log in block order across windows', async () => {
    const { run } = scan(1_000n, 31_000n, 10_000n);
    const logs = await run();
    expect(logs).toHaveLength(30_001);
    expect(logs[0]).toBe(1_000n);
    expect(logs.at(-1)).toBe(31_000n);
    expect([...logs].sort((a, b) => (a < b ? -1 : 1))).toEqual(logs);
  });

  it('covers the range exactly once, with no gap and no overlap', async () => {
    const { rpc, run } = scan(0n, 25_000n, 10_000n);
    await run();
    const windows = [...rpc.seen].sort((a, b) => (a.from < b.from ? -1 : 1));
    expect(windows[0].from).toBe(0n);
    expect(windows.at(-1)!.to).toBe(25_000n);
    for (let i = 1; i < windows.length; i++) expect(windows[i].from).toBe(windows[i - 1].to + 1n);
  });

  it('narrows to a cap tighter than the default and keeps the narrowed width', async () => {
    const { rpc, run } = scan(0n, 40_000n, 2_000n);
    const logs = await run();

    expect(logs).toHaveLength(40_001);
    expect(logs[0]).toBe(0n);
    expect(logs.at(-1)).toBe(40_000n);
    expect(Math.max(...rpc.seen.map((w) => Number(w.to - w.from + 1n)))).toBeLessThanOrEqual(2_000);

    // The cap is discovered once, by halving 9,000 down past 2,000 — three rejections — and then
    // every remaining window is claimed at the narrowed width. Rediscovering it per window would
    // cost three more each time.
    expect(rpc.rejected).toBe(3);
    expect(rpc.seen.length).toBeLessThan(2 * Math.ceil(40_001 / 2_000));
  });

  it('honours a configured maxRange without a discovery round trip', async () => {
    const { rpc, run } = scan(0n, 4_000n, 1_000n, 1_000n);
    await run();
    expect(rpc.seen).toHaveLength(5);
  });

  it('rethrows a failure that is not about the range', async () => {
    const boom = async () => {
      throw new Error('fetch failed');
    };
    await expect(scanLogs({ fromBlock: 0n, toBlock: 100n, subject: 'test logs', query: boom })).rejects.toThrow('fetch failed');
  });

  it('refuses a chain-sized range before sending anything', async () => {
    const { rpc, run } = scan(0n, 46_979_411n, 10_000n);
    await expect(run()).rejects.toBeInstanceOf(LogRangeUnboundedError);
    await expect(run()).rejects.toThrow(/deploymentBlock/);
    expect(rpc.seen).toHaveLength(0);
  });

  it('accepts a deployment-sized range on the same chain', async () => {
    const { run } = scan(46_634_819n, 46_979_411n, 10_000n);
    await expect(run()).resolves.toHaveLength(344_593);
  });

  it('is empty for a range that has not been reached yet', async () => {
    const { rpc, run } = scan(100n, 99n, 10_000n);
    await expect(run()).resolves.toEqual([]);
    expect(rpc.seen).toHaveLength(0);
  });
});
