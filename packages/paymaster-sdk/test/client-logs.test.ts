import { keccak256, toBytes, type Hex } from 'viem';
import { describe, expect, it } from 'vitest';
import { GianoPaymasterClient, type PaymasterPublicClient } from '../src/client';

const ADDRESS = '0xf98b56de62ce88cEb70A9155582248cDBf2D0718' as const;
/** Deep enough that a genesis-anchored read would be refused; the point is that it is not. */
const HEAD = 46_979_411n;

const tenantId = (slug: string): Hex => `0x${keccak256(toBytes(slug)).slice(2, 34)}` as Hex;

type Registration = { block: bigint; slug: string };
type Call = { fromBlock: bigint; toBlock: bigint };

/** A node with Base Sepolia's 10,000-block cap, serving `TenantRegistered` logs. */
function publicClient(head: bigint, registrations: readonly Registration[], cap = 10_000n) {
  const calls: Call[] = [];
  const client = {
    getBlockNumber: async () => head,
    getContractEvents: async ({ fromBlock, toBlock }: Call) => {
      if (toBlock - fromBlock + 1n > cap) {
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
  it('is one query at the head, whatever the chain’s depth', async () => {
    const { calls, client } = publicClient(HEAD, [{ block: HEAD - 40n, slug: 'acme' }]);
    const page = await new GianoPaymasterClient({ address: ADDRESS, publicClient: client }).getTenantSlugs();

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ fromBlock: HEAD - 8_999n, toBlock: HEAD });
    expect([...page.slugs.values()]).toEqual(['acme']);
  });

  it('reports the window it read and where the previous one is', async () => {
    const { client } = publicClient(HEAD, []);
    const page = await new GianoPaymasterClient({ address: ADDRESS, publicClient: client }).getTenantSlugs();

    expect(page).toMatchObject({
      fromBlock: HEAD - 8_999n,
      toBlock: HEAD,
      older: { fromBlock: HEAD - 17_999n, toBlock: HEAD - 9_000n },
    });
  });

  it('omits a registration older than the window rather than widening for it', async () => {
    const { calls, client } = publicClient(HEAD, [
      { block: HEAD - 40n, slug: 'recent' },
      { block: HEAD - 500_000n, slug: 'ancient' },
    ]);
    const page = await new GianoPaymasterClient({ address: ADDRESS, publicClient: client }).getTenantSlugs();

    expect([...page.slugs.values()]).toEqual(['recent']);
    expect(calls).toHaveLength(1);
  });

  it('finds the older registration when paged back to it', async () => {
    const { client } = publicClient(HEAD, [{ block: HEAD - 12_000n, slug: 'ancient' }]);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client });

    const first = await paymaster.getTenantSlugs();
    expect(first.slugs.size).toBe(0);

    const second = await paymaster.getTenantSlugs(first.older);
    expect([...second.slugs.values()]).toEqual(['ancient']);
  });

  it('narrows to a tighter node cap once and keeps the narrowed span', async () => {
    const { calls, client } = publicClient(HEAD, [], 2_000n);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client });

    const first = await paymaster.getTenantSlugs();
    expect(first.toBlock - first.fromBlock + 1n).toBe(1_125n);

    // The second read asks for the discovered span directly rather than re-failing its way down.
    const before = calls.length;
    const second = await paymaster.getTenantSlugs();
    expect(calls.length - before).toBe(1);
    expect(second.toBlock - second.fromBlock + 1n).toBe(1_125n);
  });
});

describe('getSponsorships', () => {
  it('reads one window at the head and says which', async () => {
    const { calls, client } = publicClient(HEAD, []);
    const page = await new GianoPaymasterClient({ address: ADDRESS, publicClient: client }).getSponsorships();

    expect(calls).toEqual([{ fromBlock: HEAD - 8_999n, toBlock: HEAD }]);
    expect(page.records).toEqual([]);
    expect(page.older).toEqual({ fromBlock: HEAD - 17_999n, toBlock: HEAD - 9_000n });
  });

  it('pages backwards through consecutive windows with no gap', async () => {
    const { calls, client } = publicClient(HEAD, []);
    const paymaster = new GianoPaymasterClient({ address: ADDRESS, publicClient: client });

    let page = await paymaster.getSponsorships();
    for (let i = 0; i < 3; i++) page = await paymaster.getSponsorships({ range: page.older });

    expect(calls).toHaveLength(4);
    for (let i = 1; i < calls.length; i++) expect(calls[i].toBlock).toBe(calls[i - 1].fromBlock - 1n);
  });

  it('honours an explicit range', async () => {
    const { calls, client } = publicClient(HEAD, []);
    await new GianoPaymasterClient({ address: ADDRESS, publicClient: client }).getSponsorships({
      range: { fromBlock: 1_000n, toBlock: 2_000n },
    });

    expect(calls).toEqual([{ fromBlock: 1_000n, toBlock: 2_000n }]);
  });
});

describe('listTenants', () => {
  /** The roster is a view call; only the labels come from logs. */
  const withRoster = (paymaster: GianoPaymasterClient, ids: readonly Hex[]) => {
    const record = { registered: true, enabled: true, hasFeeOverride: false, withdrawAddress: ADDRESS, balance: 0n, deficit: 0n, feeWeiOverride: 0n };
    (paymaster as unknown as { read: unknown }).read = async (fn: string) => {
      if (fn === 'defaultFeeWei') return 0n;
      if (fn === 'tenantCount') return BigInt(ids.length);
      if (fn === 'getTenants') return [ids, ids.map(() => record)];
      throw new Error(`unexpected read ${fn}`);
    };
    return paymaster;
  };

  it('returns every tenant even when only some have a label in the window', async () => {
    const { client } = publicClient(HEAD, [{ block: HEAD - 10n, slug: 'labelled' }]);
    const ids = [tenantId('labelled'), tenantId('registered-long-ago')];

    const tenants = await withRoster(new GianoPaymasterClient({ address: ADDRESS, publicClient: client }), ids).listTenants({ withSlugs: true });

    // The roster is complete; the label is what is best-effort.
    expect(tenants).toHaveLength(2);
    expect(tenants.map((tenant) => tenant.slug)).toEqual(['labelled', undefined]);
    expect(tenants.map((tenant) => tenant.id)).toEqual(ids);
  });

  it('reads no logs at all when slugs are not asked for', async () => {
    const { calls, client } = publicClient(HEAD, []);
    await withRoster(new GianoPaymasterClient({ address: ADDRESS, publicClient: client }), [tenantId('a')]).listTenants();

    expect(calls).toHaveLength(0);
  });
});
