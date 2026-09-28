import { describe, expect, it } from 'vitest';
import { pollRange } from '../src/services/paymaster-watcher.js';

/** Base Sepolia's cap. Every window the watcher asks for has to fit under it. */
const RPC_LOG_RANGE_CAP = 10_000n;

const span = ({ from, to }: { from: bigint; to: bigint }) => to - from + 1n;

describe('pollRange', () => {
  it('looks back a bounded window on a cold start', () => {
    expect(pollRange({ head: 46_979_411n, confirmations: 2, cursor: null })).toEqual({
      from: 46_974_409n,
      to: 46_979_409n,
    });
  });

  it('resumes from the block after the cursor', () => {
    expect(pollRange({ head: 1_000n, confirmations: 2, cursor: 900n })).toEqual({ from: 901n, to: 998n });
  });

  it('holds back the unconfirmed head', () => {
    expect(pollRange({ head: 1_000n, confirmations: 5, cursor: 990n }).to).toBe(995n);
  });

  it('stays under the RPC cap when the backlog is wider than one query', () => {
    // A watcher down for a day on a two-second chain comes back ~43,000 blocks behind.
    const range = pollRange({ head: 46_979_411n, confirmations: 2, cursor: 46_936_000n });

    expect(range.from).toBe(46_936_001n);
    expect(span(range)).toBeLessThan(RPC_LOG_RANGE_CAP);
  });

  it('catches up over successive passes rather than stalling on one refused query', () => {
    const head = 46_979_411n;
    let cursor = 46_900_000n;
    let passes = 0;

    for (; passes < 100; passes++) {
      const range = pollRange({ head, confirmations: 2, cursor });
      expect(span(range)).toBeLessThan(RPC_LOG_RANGE_CAP);
      if (range.to <= cursor) break;
      cursor = range.to;
    }

    expect(cursor).toBe(head - 2n);
    expect(passes).toBeLessThan(20);
  });

  it('yields an empty pass once the cursor has reached the confirmed head', () => {
    const range = pollRange({ head: 1_000n, confirmations: 2, cursor: 998n });
    expect(range.to).toBeLessThan(range.from);
  });

  it('does not go below genesis on a chain shallower than the lookback', () => {
    expect(pollRange({ head: 3n, confirmations: 2, cursor: null })).toEqual({ from: 0n, to: 1n });
    expect(pollRange({ head: 1n, confirmations: 5, cursor: null })).toEqual({ from: 0n, to: 0n });
  });
});
