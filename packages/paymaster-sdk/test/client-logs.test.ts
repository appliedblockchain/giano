import { keccak256, toBytes, type Hex } from 'viem';
import { describe, expect, it, vi } from 'vitest';
import { GianoPaymasterClient } from '../src/client';
import { LogRangeUnboundedError } from '../src/errors';
import type { PaymasterPublicClient } from '../src/client';

const ADDRESS = '0xf98b56de62ce88cEb70A9155582248cDBf2D0718' as const;
const DEPLOYED_AT = 46_634_819n;

/** The tenant id a slug hashes to is irrelevant here; only that distinct slugs stay distinct. */
const tenantId = (slug: string): Hex => `0x${keccak256(toBytes(slug)).slice(2, 34)}` as Hex;

type Call = { fromBlock: bigint; toBlock: bigint };

function publicClient(head: bigint, registrations: Array<{ block: bigint; slug: string }>) {
  const calls: Call[] = [];
  const client = {
    getBlockNumber: async () => head,
    getContractEvents: async ({ fromBlock, toBlock }: { fromBlock: bigint; toBlock: bigint }) => {
      if (toBlock - fromBlock + 1n > 10_000n) {
        throw Object.assign(new Error('eth_getLogs is limited to a 10,000 range'), { code: -32614 });
      }
      calls.push({ fromBlock, toBlock });
      return registrations
        .filter((entry) => entry.block >= fromBlock && entry.block <= toBlock)
        .map((entry) => ({ args: { tenantId: tenantId(entry.slug), slug: entry.slug } }));
    },
  };
  return { calls, client: client as unknown as PaymasterPublicClient };
}

describe('getTenantSlugs', () => {
  it('reads the whole deployment in windows the node will serve', async () => {
    const { calls, client } = publicClient(DEPLOYED_AT + 40_000n, [
      { block: DEPLOYED_AT + 12n, slug: 'acme' },
      { block: DEPLOYED_AT + 31_400n, slug: 'globex' },
    ]);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client, deploymentBlock: DEPLOYED_AT });

    const slugs = await paymaster.getTenantSlugs();

    expect([...slugs.values()].sort()).toEqual(['acme', 'globex']);
    expect(calls.length).toBeGreaterThan(1);
    expect(Math.max(...calls.map((call) => Number(call.toBlock - call.fromBlock + 1n)))).toBeLessThanOrEqual(10_000);
    expect(Math.min(...calls.map((call) => Number(call.fromBlock)))).toBe(Number(DEPLOYED_AT));
  });

  it('never looks below the deployment block', async () => {
    const { calls, client } = publicClient(DEPLOYED_AT + 100n, []);
    await new GianoPaymasterClient({ address: ADDRESS, publicClient: client, deploymentBlock: DEPLOYED_AT }).getTenantSlugs();
    expect(calls.every((call) => call.fromBlock >= DEPLOYED_AT)).toBe(true);
  });

  it('rereads only the blocks added since the last scan', async () => {
    const { calls, client } = publicClient(DEPLOYED_AT + 40_000n, [{ block: DEPLOYED_AT + 12n, slug: 'acme' }]);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client, deploymentBlock: DEPLOYED_AT });

    await paymaster.getTenantSlugs();
    const firstScan = calls.length;

    vi.spyOn(client, 'getBlockNumber').mockResolvedValue(DEPLOYED_AT + 40_050n);
    const slugs = await paymaster.getTenantSlugs();

    // The refresh covers the 50 new blocks and nothing else, but still answers with every slug.
    expect(calls.slice(firstScan)).toEqual([{ fromBlock: DEPLOYED_AT + 40_001n, toBlock: DEPLOYED_AT + 40_050n }]);
    expect([...slugs.values()]).toEqual(['acme']);
  });

  it('does not let an explicit floor poison the cache', async () => {
    const { client } = publicClient(DEPLOYED_AT + 40_000n, [
      { block: DEPLOYED_AT + 12n, slug: 'acme' },
      { block: DEPLOYED_AT + 31_400n, slug: 'globex' },
    ]);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client, deploymentBlock: DEPLOYED_AT });

    const recent = await paymaster.getTenantSlugs(DEPLOYED_AT + 20_000n);
    expect([...recent.values()]).toEqual(['globex']);

    expect([...(await paymaster.getTenantSlugs()).values()].sort()).toEqual(['acme', 'globex']);
  });

  it('refuses to scan from genesis when no deployment block is configured', async () => {
    const { calls, client } = publicClient(46_979_411n, []);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client });

    await expect(paymaster.getTenantSlugs()).rejects.toBeInstanceOf(LogRangeUnboundedError);
    expect(calls).toHaveLength(0);
  });
});

describe('getSponsorships', () => {
  it('starts at the deployment block rather than at genesis', async () => {
    const { calls, client } = publicClient(DEPLOYED_AT + 25_000n, []);
    await new GianoPaymasterClient({ address: ADDRESS, publicClient: client, deploymentBlock: DEPLOYED_AT }).getSponsorships();

    expect(calls[0].fromBlock).toBe(DEPLOYED_AT);
    expect(calls.at(-1)!.toBlock).toBe(DEPLOYED_AT + 25_000n);
  });

  it('honours an explicit range', async () => {
    const { calls, client } = publicClient(DEPLOYED_AT + 25_000n, []);
    await new GianoPaymasterClient({ address: ADDRESS, publicClient: client, deploymentBlock: DEPLOYED_AT }).getSponsorships({
      fromBlock: DEPLOYED_AT + 1_000n,
      toBlock: DEPLOYED_AT + 2_000n,
    });

    expect(calls).toEqual([{ fromBlock: DEPLOYED_AT + 1_000n, toBlock: DEPLOYED_AT + 2_000n }]);
  });
});

describe('withWallet', () => {
  it('carries the log settings to the rebound client', () => {
    const { client } = publicClient(DEPLOYED_AT, []);
    const rebound = new GianoPaymasterClient({
      address: ADDRESS,
      publicClient: client,
      deploymentBlock: DEPLOYED_AT,
      maxLogRange: 2_000n,
    }).withWallet({} as never);

    expect(rebound.deploymentBlock).toBe(DEPLOYED_AT);
    expect(rebound.maxLogRange).toBe(2_000n);
  });
});
