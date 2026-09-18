import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_LOG_WINDOW, isBlockRangeError, readWindow, resolveWindow } from '../src/log-window';
import type { PaymasterPublicClient } from '../src/client';

/** The rejection Base Sepolia's public endpoint returns, as viem wraps it. */
const rejection = () => {
  const rpc = Object.assign(new Error('eth_getLogs is limited to a 10,000 range'), { code: -32614 });
  return Object.assign(new Error('An internal error was received.'), { shortMessage: 'An internal error was received.', cause: rpc });
};

const at = (head: bigint) => ({ getBlockNumber: async () => head }) as unknown as PaymasterPublicClient;

describe('isBlockRangeError', () => {
  it('recognises the rejection through viem’s wrapper', () => {
    expect(isBlockRangeError(rejection())).toBe(true);
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

describe('resolveWindow', () => {
  it('defaults to one window ending at the head', async () => {
    expect(await resolveWindow(at(46_979_411n), undefined, DEFAULT_LOG_WINDOW)).toEqual({
      fromBlock: 46_970_412n,
      toBlock: 46_979_411n,
    });
  });

  it('costs the same on a deep chain as on a shallow one', async () => {
    const shallow = await resolveWindow(at(20_000n), undefined, 9_000n);
    const deep = await resolveWindow(at(46_979_411n), undefined, 9_000n);
    expect(deep.toBlock - deep.fromBlock).toBe(shallow.toBlock - shallow.fromBlock);
  });

  it('does not reach below genesis on a young chain', async () => {
    expect(await resolveWindow(at(120n), undefined, 9_000n)).toEqual({ fromBlock: 0n, toBlock: 120n });
  });

  it('refuses a window that cannot span a block', async () => {
    await expect(resolveWindow(at(1_000n), undefined, 0n)).rejects.toThrow(RangeError);
    await expect(resolveWindow(at(1_000n), undefined, -5n)).rejects.toThrow(/at least one block/);
  });

  it('honours an explicit range', async () => {
    expect(await resolveWindow(at(46_979_411n), { fromBlock: 100n, toBlock: 200n }, 9_000n)).toEqual({
      fromBlock: 100n,
      toBlock: 200n,
    });
  });

  it('clamps a range asking past the head', async () => {
    expect(await resolveWindow(at(1_000n), { toBlock: 9_999_999n }, 100n)).toEqual({ fromBlock: 901n, toBlock: 1_000n });
  });

  it('leaves a range entirely in the future inverted, for readWindow to answer as empty', async () => {
    const range = await resolveWindow(at(1_000n), { fromBlock: 5_000n, toBlock: 6_000n }, 100n);
    expect(range.fromBlock).toBeGreaterThan(range.toBlock);
  });
});

describe('readWindow', () => {
  /** A node serving one log per block, refusing any query wider than `cap`. */
  const node = (cap: bigint) => {
    const seen: Array<{ fromBlock: bigint; toBlock: bigint }> = [];
    return {
      seen,
      query: async ({ fromBlock, toBlock }: { fromBlock: bigint; toBlock: bigint }) => {
        if (toBlock - fromBlock + 1n > cap) throw rejection();
        seen.push({ fromBlock, toBlock });
        const logs: bigint[] = [];
        for (let block = fromBlock; block <= toBlock; block++) logs.push(block);
        return logs;
      },
    };
  };

  it('is one query when the node serves the window', async () => {
    const rpc = node(10_000n);
    const page = await readWindow({ fromBlock: 1_000n, toBlock: 9_999n }, rpc.query);

    expect(rpc.seen).toHaveLength(1);
    expect(page.logs).toHaveLength(9_000);
    expect(page.fromBlock).toBe(1_000n);
    expect(page.toBlock).toBe(9_999n);
  });

  it('narrows to a tighter cap and reports the range it actually covered', async () => {
    const rpc = node(2_000n);
    const page = await readWindow({ fromBlock: 40_000n, toBlock: 48_999n }, rpc.query);

    // Halving 9,000 past 2,000 takes three refusals; the fourth attempt is served.
    expect(rpc.seen).toHaveLength(1);
    expect(page.toBlock).toBe(48_999n);
    expect(page.fromBlock).toBe(47_875n);
    expect(page.logs).toHaveLength(1_125);
  });

  it('hands the narrowed span back so the next read starts there', async () => {
    const onNarrow = vi.fn();
    await readWindow({ fromBlock: 40_000n, toBlock: 48_999n }, node(2_000n).query, onNarrow);

    expect(onNarrow).toHaveBeenLastCalledWith(1_125n);
  });

  it('offers the adjacent older window, matched to the span served', async () => {
    const page = await readWindow({ fromBlock: 10_000n, toBlock: 18_999n }, node(10_000n).query);
    expect(page.older).toEqual({ fromBlock: 1_000n, toBlock: 9_999n });
  });

  it('pages back to genesis and then stops offering', async () => {
    const page = await readWindow({ fromBlock: 0n, toBlock: 8_999n }, node(10_000n).query);
    expect(page.older).toBeUndefined();
  });

  it('does not let the oldest window reach below genesis', async () => {
    const page = await readWindow({ fromBlock: 500n, toBlock: 9_499n }, node(10_000n).query);
    expect(page.older).toEqual({ fromBlock: 0n, toBlock: 499n });
  });

  it('answers an empty range without troubling the node', async () => {
    const rpc = node(10_000n);
    const page = await readWindow({ fromBlock: 101n, toBlock: 100n }, rpc.query);

    expect(page.logs).toEqual([]);
    expect(rpc.seen).toHaveLength(0);
  });

  it('rethrows a failure that is not about the range', async () => {
    const boom = async () => {
      throw new Error('fetch failed');
    };
    await expect(readWindow({ fromBlock: 0n, toBlock: 100n }, boom)).rejects.toThrow('fetch failed');
  });

  it('gives up rather than narrowing forever against a node that refuses everything', async () => {
    // The node's own rejection surfaces once narrowing bottoms out, rather than a loop or a
    // silently empty answer.
    await expect(readWindow({ fromBlock: 0n, toBlock: 8_999n }, node(1n).query)).rejects.toThrow('An internal error was received.');
  });
});
