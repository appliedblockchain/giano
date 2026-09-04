import {
  encodeRemoveOwnerAtIndex,
  ownerFingerprint,
  publicKeyOwnerBytes,
  type RegistryCredential,
  type WalletManagementApi,
} from '@appliedblockchain/giano-wallet-core';
import { getAddress, pad, type Hex } from 'viem';
import { describe, expect, it, vi } from 'vitest';
import { createManagementController, type ManagementFlow } from '../src/management/controller';
import type { SponsorshipPreflight, WalletRuntime, WalletRuntimes } from '../src/runtimes';

const WALLET = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const;

const keyA = { x: pad('0x0a', { size: 32 }) as Hex, y: pad('0x1a', { size: 32 }) as Hex };
const keyB = { x: pad('0x0b', { size: 32 }) as Hex, y: pad('0x1b', { size: 32 }) as Hex };
const bytesA = publicKeyOwnerBytes(keyA.x, keyA.y);
const bytesB = publicKeyOwnerBytes(keyB.x, keyB.y);

const credentialA: RegistryCredential = {
  credentialId: 'cred-a',
  walletAddress: WALLET,
  name: 'My passkey',
  publicKeyX: keyA.x,
  publicKeyY: keyA.y,
  transports: ['internal'],
  createdAt: '2026-01-01T00:00:00Z',
  removedAt: null,
};

type ChainState = {
  deployed: boolean;
  /** null entries are removal holes — indices are never reused (WM-02). */
  owners: (Hex | null)[];
  unreachable?: boolean;
};

type Harness = ReturnType<typeof harness>;

function harness({
  chains = { 31337: { deployed: true, owners: [bytesA, bytesB] } } as Record<number, ChainState>,
  credentials = [credentialA] as RegistryCredential[],
  preflight = { state: 'sponsored' } as SponsorshipPreflight,
  session = 'token' as string | null,
} = {}) {
  /** Ordered record of everything consequential, for ordering assertions. */
  const events: string[] = [];
  let sessionToken = session;

  const runtimeCache = new Map<number, WalletRuntime>();
  const runtimeFor = (chainId: number): WalletRuntime => {
    const cached = runtimeCache.get(chainId);
    if (cached) return cached;
    const chain = chains[chainId];
    const runtime = {
      chainId,
      chainName: `Chain ${chainId}`,
      factoryAddress: '0x1111111111111111111111111111111111111111',
      injection: {
        getSessionToken: () => sessionToken,
        encodeUserId: vi.fn(async () => new Uint8Array(37)),
        logout: vi.fn(async () => {
          events.push('logout');
          sessionToken = null;
        }),
        signInWithExistingPasskey: vi.fn(async () => ({ walletAddress: WALLET })),
      },
      provider: {
        getSmartAccount: () => ({}),
        on: vi.fn(),
        request: vi.fn(async ({ method, params }: { method: string; params?: unknown[] }) => {
          if (method === 'eth_sendTransaction') {
            events.push(`send:${chainId}:${(params?.[0] as { data: Hex }).data}`);
            return '0xhash';
          }
          if (method === 'waitForUserOperationReceipt') {
            events.push(`receipt:${chainId}`);
            return { success: true };
          }
          return undefined;
        }),
      },
      publicClient: {
        getCode: async () => {
          if (chain.unreachable) throw new Error('chain unreachable');
          return chain.deployed ? '0x6001' : undefined;
        },
        readContract: async ({ functionName, args }: { functionName: string; args?: [bigint] }) => {
          if (chain.unreachable) throw new Error('chain unreachable');
          if (functionName === 'nextOwnerIndex') return BigInt(chain.owners.length);
          return chain.owners[Number(args![0])] ?? '0x';
        },
      },
      isAccountDeployed: async () => chain.deployed,
      checkSponsorship: vi.fn(async () => {
        events.push(`preflight:${chainId}`);
        return preflight;
      }),
      externalUserId: 'user',
    } as unknown as WalletRuntime;
    runtimeCache.set(chainId, runtime);
    return runtime;
  };

  const runtimes: WalletRuntimes = {
    servedChainIds: Object.keys(chains).map(Number),
    runtimeFor,
    descriptorFor: (chainId) => ({ chainId, name: `Chain ${chainId}` }) as never,
  };

  const api = {
    me: vi.fn(async () => ({ externalUserId: 'user', walletAddress: WALLET, credentialId: 'cred-a' })),
    listCredentials: vi.fn(async () => credentials),
    renameCredential: vi.fn(async () => ({ ok: true, name: 'renamed' })),
    markCredentialRemoved: vi.fn(async () => {
      events.push('registry:mark-removed');
      return { ok: true, removedCurrentSession: false };
    }),
    openPendingAddition: vi.fn(async () => {
      events.push('slot:open');
      return { id: 'slot-1', claimCode: 'AB3D9KFM', expiresAt: '2026-01-01T00:05:00Z' };
    }),
    getPendingAddition: vi.fn(async () => ({ id: 'slot-1', status: 'open', expiresAt: '2026-01-01T00:05:00Z', publicKey: null })),
    declinePendingAddition: vi.fn(async () => {
      events.push('slot:decline');
      return { ok: true };
    }),
    completePendingAddition: vi.fn(async () => {
      events.push('registry:bind');
      return { ok: true, credentialId: 'cred-b' };
    }),
    claimPendingAddition: vi.fn(),
    fillPendingAddition: vi.fn(),
    recordOwnerEvent: vi.fn(async () => {
      events.push('registry:owner-event');
      return { ok: true };
    }),
  } as unknown as WalletManagementApi;

  const depositPasskey = vi.fn(async () => {
    events.push('ceremony:create-passkey');
    return { publicKey: keyB, fingerprint: ownerFingerprint(bytesB) };
  });

  const controller = createManagementController({
    runtimes,
    config: { walletApiUrl: '/api', branding: { name: 'Test Wallet' } },
    pollIntervalMs: 5,
    internals: { api, depositPasskey },
  });

  return { controller, api, events, depositPasskey, runtimeFor, chains };
}

async function settle(h: Harness, predicate: () => boolean) {
  await vi.waitFor(() => expect(predicate()).toBe(true), { timeout: 2000 });
}

const flowIs = (h: Harness, type: string, step?: string) => () =>
  h.controller.flow?.type === type && (step === undefined || (h.controller.flow as { step?: string }).step === step);

describe('loading the set (WK-17, WM-01…WM-06)', () => {
  it('reads the owner set from the chain and joins the registry by owner bytes', async () => {
    const h = harness();
    await h.controller.load();
    const { state } = h.controller;
    expect(state.view).toBe('set');
    expect(state.walletAddress).toBe(WALLET);
    expect(state.owners).toHaveLength(2);
    expect(state.owners[0]).toMatchObject({ name: 'My passkey', credentialId: 'cred-a', isCurrent: true, fingerprint: ownerFingerprint(bytesA) });
    // an on-chain owner the registry has no row for is still shown (WM-04, inverse case)
    expect(state.owners[1]).toMatchObject({ name: null, credentialId: null, isCurrent: false });
    expect(state.deployed).toBe(true);
  });

  it('shows registry rows the chain does not back as strays, never omitted (WM-04)', async () => {
    const h = harness({ chains: { 31337: { deployed: true, owners: [bytesB] } } });
    await h.controller.load();
    expect(h.controller.state.owners).toHaveLength(1);
    expect(h.controller.state.strays).toHaveLength(1);
    expect(h.controller.state.strays[0]).toMatchObject({ credentialId: 'cred-a', name: 'My passkey' });
  });

  it('surfaces divergence between served chains as a problem (WM-06)', async () => {
    const h = harness({
      chains: {
        31337: { deployed: true, owners: [bytesA, bytesB] },
        31338: { deployed: true, owners: [bytesA] },
      },
    });
    await h.controller.load();
    expect(h.controller.state.divergent).toBe(true);
  });

  it('reports an unreadable chain as its own state, never an empty list (WM-05)', async () => {
    const h = harness({ chains: { 31337: { deployed: true, owners: [bytesA], unreachable: true } } });
    await h.controller.load();
    expect(h.controller.state.view).toBe('unreadable');
    expect(h.controller.state.owners).toHaveLength(0);
    expect(h.controller.state.chains[0]).toMatchObject({ deployed: null, error: expect.stringContaining('unreachable') });
  });

  it('is signed-out without a session token (WM-57)', async () => {
    const h = harness({ session: null });
    await h.controller.load();
    expect(h.controller.state.view).toBe('signed-out');
  });
});

describe('adding a passkey (WM-14, WM-15, WM-20)', () => {
  it('pre-flights sponsorship BEFORE any passkey ceremony; a refusal costs no prompt (WM-68, WK-13)', async () => {
    const h = harness({
      preflight: { state: 'refused', reason: 'wallet-management-not-sponsored', message: 'off', ruleResults: [] },
    });
    await h.controller.load();
    h.controller.startAddThisDevice();
    await settle(h, flowIs(h, 'refused'));
    expect(h.controller.flow).toMatchObject({ type: 'refused', reason: 'wallet-management-not-sponsored' });
    expect(h.depositPasskey).not.toHaveBeenCalled();
    expect(h.events.filter((event) => event.startsWith('send:'))).toHaveLength(0);
  });

  it('writes the chain before the registry binds, and binds only the chains that confirmed (WM-15, WK-18)', async () => {
    const h = harness({
      chains: {
        31337: { deployed: true, owners: [bytesA] },
        31338: { deployed: false, owners: [] }, // skipped: not deployed (WM-46)
      },
    });
    await h.controller.load();
    h.controller.startAddThisDevice();
    await settle(h, flowIs(h, 'add', 'confirm-fingerprint'));

    const confirm = h.controller.flow as Extract<ManagementFlow, { step: 'confirm-fingerprint' }>;
    confirm.setName('Backup');
    (h.controller.flow as Extract<ManagementFlow, { step: 'confirm-fingerprint' }>).approve();
    await settle(h, flowIs(h, 'add', 'done'));

    // ordering: ceremony → send → receipt → THEN the registry bind
    const bind = h.events.indexOf('registry:bind');
    expect(bind).toBeGreaterThan(h.events.indexOf('receipt:31337'));
    expect(h.api.completePendingAddition).toHaveBeenCalledWith('slot-1', { chainIds: [31337], name: 'Backup' });

    const done = h.controller.flow as Extract<ManagementFlow, { step: 'done'; type: 'add' }>;
    expect(done.ok).toBe(true);
    expect(done.appliedChainIds).toEqual([31337]);
    expect(done.chains.map((row) => row.state)).toEqual(['confirmed', 'skipped']);
  });

  it('never binds when nothing confirmed on-chain', async () => {
    const h = harness();
    const runtime = h.runtimeFor(31337);
    (runtime.provider.request as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('bundler down'));
    await h.controller.load();
    h.controller.startAddThisDevice();
    await settle(h, flowIs(h, 'add', 'confirm-fingerprint'));
    (h.controller.flow as Extract<ManagementFlow, { step: 'confirm-fingerprint' }>).approve();
    await settle(h, flowIs(h, 'add', 'done'));
    expect(h.api.completePendingAddition).not.toHaveBeenCalled();
    expect((h.controller.flow as Extract<ManagementFlow, { step: 'done'; type: 'add' }>).ok).toBe(false);
  });

  it('recomputes the cross-device fingerprint from the key AS RECEIVED, never from a backend claim (WM-20, WK-18)', async () => {
    const h = harness();
    // the backend's slot carries the key AND a lying fingerprint field the controller must ignore
    (h.api.getPendingAddition as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'slot-1',
      status: 'filled',
      expiresAt: '2026-01-01T00:05:00Z',
      publicKey: keyB,
      fingerprint: 'FAK-EEE',
    });
    await h.controller.load();
    h.controller.startAddSecondDevice();
    await settle(h, flowIs(h, 'add', 'confirm-fingerprint'));
    const confirm = h.controller.flow as Extract<ManagementFlow, { step: 'confirm-fingerprint' }>;
    expect(confirm.fingerprint).toBe(ownerFingerprint(publicKeyOwnerBytes(keyB.x, keyB.y)));
    expect(confirm.fingerprint).not.toBe('FAK-EEE');
  });

  it('declines a mismatch: the slot is declined, counted, and nothing is added (WM-21, WM-52)', async () => {
    const h = harness();
    (h.api.getPendingAddition as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'slot-1',
      status: 'filled',
      expiresAt: '2026-01-01T00:05:00Z',
      publicKey: keyB,
    });
    await h.controller.load();
    h.controller.startAddSecondDevice();
    await settle(h, flowIs(h, 'add', 'confirm-fingerprint'));
    (h.controller.flow as Extract<ManagementFlow, { step: 'confirm-fingerprint' }>).decline();
    await settle(h, flowIs(h, 'add', 'declined'));
    expect(h.api.declinePendingAddition).toHaveBeenCalledWith('slot-1');
    expect(h.events.filter((event) => event.startsWith('send:'))).toHaveLength(0);
  });

  it('surfaces an expired slot distinctly from a network failure (WM-23)', async () => {
    const h = harness();
    (h.api.getPendingAddition as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'slot-1',
      status: 'expired',
      expiresAt: '2026-01-01T00:05:00Z',
      publicKey: null,
    });
    await h.controller.load();
    h.controller.startAddSecondDevice();
    await settle(h, flowIs(h, 'add', 'expired'));
  });
});

describe('removal (WM-27…WM-32, WK-18, WK-19)', () => {
  it('re-reads the removal index from EACH chain immediately before use (WM-29)', async () => {
    // the same owner sits at different indices on the two chains (a removal hole on B)
    const h = harness({
      chains: {
        31337: { deployed: true, owners: [bytesA, bytesB] }, // bytesB at index 1
        31338: { deployed: true, owners: [null, bytesA, bytesB] }, // bytesB at index 2
      },
    });
    await h.controller.load();
    const target = h.controller.state.owners.find((owner) => owner.ownerBytes === bytesB)!;
    h.controller.startRemove(target);
    (h.controller.flow as Extract<ManagementFlow, { type: 'remove'; step: 'confirm' }>).approve();
    await settle(h, flowIs(h, 'remove', 'done'));

    const sends = h.events.filter((event) => event.startsWith('send:'));
    expect(sends).toEqual([`send:31337:${encodeRemoveOwnerAtIndex(1, bytesB)}`, `send:31338:${encodeRemoveOwnerAtIndex(2, bytesB)}`]);
  });

  it('refuses to open a removal flow for the last remaining owner (WM-28, WK-19)', async () => {
    const h = harness({ chains: { 31337: { deployed: true, owners: [bytesA] } } });
    await h.controller.load();
    h.controller.startRemove(h.controller.state.owners[0]);
    expect(h.controller.flow).toBeNull();
    expect(h.controller.state.error).toMatch(/last remaining credential/);
    expect(h.events.filter((event) => event.startsWith('send:'))).toHaveLength(0);
  });

  it('refuses legibly on a chain where the owner is the last one, instead of submitting a revert', async () => {
    const h = harness({
      chains: {
        31337: { deployed: true, owners: [bytesA, bytesB] },
        31338: { deployed: true, owners: [bytesB] }, // last owner THERE
      },
    });
    await h.controller.load();
    const target = h.controller.state.owners.find((owner) => owner.ownerBytes === bytesB)!;
    h.controller.startRemove(target);
    (h.controller.flow as Extract<ManagementFlow, { type: 'remove'; step: 'confirm' }>).approve();
    await settle(h, flowIs(h, 'remove', 'done'));
    const done = h.controller.flow as Extract<ManagementFlow, { type: 'remove'; step: 'done' }>;
    expect(done.chains.find((row) => row.chainId === 31338)).toMatchObject({ state: 'failed', detail: expect.stringMatching(/last owner/) });
    expect(h.events.filter((event) => event.startsWith('send:31338'))).toHaveLength(0);
  });

  it('marks the registry only after the chain confirmed, and ends the session when the current credential was removed (WM-30)', async () => {
    const h = harness();
    (h.api.markCredentialRemoved as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      h.events.push('registry:mark-removed');
      return { ok: true, removedCurrentSession: true };
    });
    await h.controller.load();
    const target = h.controller.state.owners.find((owner) => owner.credentialId === 'cred-a')!;
    h.controller.startRemove(target);
    const confirm = h.controller.flow as Extract<ManagementFlow, { type: 'remove'; step: 'confirm' }>;
    expect(confirm.endsThisSession).toBe(true);
    confirm.approve();
    await settle(h, flowIs(h, 'remove', 'done'));

    expect(h.events.indexOf('registry:mark-removed')).toBeGreaterThan(h.events.indexOf('receipt:31337'));
    expect((h.controller.flow as Extract<ManagementFlow, { type: 'remove'; step: 'done' }>).endedSession).toBe(true);
    expect(h.events).toContain('logout');
    h.controller.dismissFlow();
    expect(h.controller.state.view).toBe('signed-out');
  });

  it('pre-flights each chain before its passkey prompt (WM-68)', async () => {
    const h = harness();
    await h.controller.load();
    const target = h.controller.state.owners.find((owner) => owner.ownerBytes === bytesB)!;
    h.controller.startRemove(target);
    (h.controller.flow as Extract<ManagementFlow, { type: 'remove'; step: 'confirm' }>).approve();
    await settle(h, flowIs(h, 'remove', 'done'));
    expect(h.events.indexOf('preflight:31337')).toBeLessThan(h.events.indexOf('send:31337:' + encodeRemoveOwnerAtIndex(1, bytesB)));
  });
});

describe('adding an externally-owned account (WM-24…WM-26)', () => {
  const checksummed = '0x52908400098527886E0F7030069857D2E4169EE7';

  async function toInput(h: Harness) {
    await h.controller.load();
    h.controller.startAddAddress();
    await settle(h, flowIs(h, 'address', 'input'));
  }

  it('validates the address: checksum, format, and not the wallet itself (WM-25)', async () => {
    const h = harness();
    await toInput(h);
    let input = h.controller.flow as Extract<ManagementFlow, { type: 'address'; step: 'input' }>;
    input.setAddress('not-an-address');
    (h.controller.flow as typeof input).continue();
    expect((h.controller.flow as typeof input).error).toBe('invalid-address');

    input = h.controller.flow as typeof input;
    input.setAddress(checksummed.toLowerCase());
    (h.controller.flow as typeof input).continue();
    expect((h.controller.flow as typeof input).error).toBe('not-checksummed');

    input = h.controller.flow as typeof input;
    input.setAddress(getAddress(WALLET));
    (h.controller.flow as typeof input).continue();
    expect((h.controller.flow as typeof input).error).toBe('own-wallet');
  });

  it('gates approval on the explicit acknowledgement of what is granted (WM-26)', async () => {
    const h = harness();
    await toInput(h);
    (h.controller.flow as Extract<ManagementFlow, { type: 'address'; step: 'input' }>).setAddress(checksummed);
    (h.controller.flow as Extract<ManagementFlow, { type: 'address'; step: 'input' }>).continue();
    const confirm = h.controller.flow as Extract<ManagementFlow, { type: 'address'; step: 'confirm' }>;
    expect(confirm.address).toBe(checksummed);
    expect(confirm.grantNotice).toMatch(/full and equal control/);

    confirm.approve(); // not acknowledged: a no-op
    expect((h.controller.flow as { step: string }).step).toBe('confirm');

    confirm.acknowledge(true);
    (h.controller.flow as Extract<ManagementFlow, { type: 'address'; step: 'confirm' }>).approve();
    await settle(h, flowIs(h, 'address', 'done'));
    expect(h.api.recordOwnerEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'owner-added', ownerKind: 'address', owner: checksummed }));
  });
});

describe('the claim flow (WM-19, WM-23)', () => {
  it('deposits against the code with no session and surfaces the fingerprint to compare', async () => {
    const h = harness({ session: null });
    h.controller.startClaimOnThisDevice();
    const input = h.controller.flow as Extract<ManagementFlow, { type: 'claim'; step: 'input' }>;
    input.setCode('AB3D9KFM');
    (h.controller.flow as typeof input).submit();
    await settle(h, flowIs(h, 'claim', 'deposited'));
    expect((h.controller.flow as Extract<ManagementFlow, { type: 'claim'; step: 'deposited' }>).fingerprint).toBe(ownerFingerprint(bytesB));
  });

  it('keys the error on the machine-readable code, distinct from a network failure', async () => {
    const h = harness({ session: null });
    h.depositPasskey.mockRejectedValue(Object.assign(new Error('expired'), { code: 'pending-expired' }));
    h.controller.startClaimOnThisDevice();
    (h.controller.flow as Extract<ManagementFlow, { type: 'claim'; step: 'input' }>).submit();
    await settle(h, flowIs(h, 'claim', 'error'));
    expect(h.controller.flow).toMatchObject({ type: 'claim', step: 'error', code: 'pending-expired' });
  });
});

describe('renaming and lifecycle', () => {
  it('renames through the registry and reloads', async () => {
    const h = harness();
    await h.controller.load();
    await h.controller.rename('cred-a', 'New name');
    expect(h.api.renameCredential).toHaveBeenCalledWith('cred-a', 'New name');
  });

  it('a dismissed flow is not resurrected by a late continuation, and its orphaned slot is declined', async () => {
    const h = harness();
    let release!: () => void;
    (h.api.openPendingAddition as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise((resolve) => (release = () => resolve({ id: 'slot-1', claimCode: 'AB3D9KFM', expiresAt: '2026-01-01T00:05:00Z' }))),
    );
    await h.controller.load();
    h.controller.startAddThisDevice();
    // wait until the flow is actually blocked on the slot opening, then dismiss
    await vi.waitFor(() => expect(h.api.openPendingAddition).toHaveBeenCalled());
    h.controller.dismissFlow();
    expect(h.controller.flow).toBeNull();

    release();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(h.controller.flow).toBeNull();
    expect(h.depositPasskey).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(h.api.declinePendingAddition).toHaveBeenCalledWith('slot-1'));
  });

  it('declines an abandoned pending addition on dismiss (WM-52)', async () => {
    const h = harness();
    await h.controller.load();
    h.controller.startAddSecondDevice();
    await settle(h, flowIs(h, 'add', 'claim-code'));
    h.controller.dismissFlow();
    await vi.waitFor(() => expect(h.api.declinePendingAddition).toHaveBeenCalledWith('slot-1'));
    expect(h.controller.flow).toBeNull();
  });
});
