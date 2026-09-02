import {
  createWalletManagementApi,
  ownerSetsDiverge,
  publicKeyOwnerBytes,
  readOwnerSet,
  type OnChainOwner,
  type OwnerSet,
  type RegistryCredential,
  type WalletManagementApi,
} from '@appliedblockchain/giano-wallet-core';
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { WalletConfig } from '../config';
import type { WalletRuntimes } from '../wallet';
import { AddAddressFlow } from './manage/AddAddressFlow';
import { AddDeviceFlow } from './manage/AddDeviceFlow';
import { AddPasskeyFlow } from './manage/AddPasskeyFlow';
import { ClaimFlow } from './manage/ClaimFlow';
import { RemoveFlow } from './manage/RemoveFlow';

/**
 * The wallet-management interface (WM-01…WM-11): every credential that can act on the
 * wallet, read from the chain, reconciled against the registry — with divergence shown
 * rather than hidden — plus the add and remove flows.
 *
 * Reached two ways with the same capabilities (WM-56): standalone on the wallet origin,
 * and from an application through `giano_openWalletManagement` (then `onClose` resolves
 * the transport request with nothing, WM-40).
 */

export type ChainOwnerSet = {
  chainId: number;
  chainName: string;
  /** null = the chain could not be read — its own state, never an empty list (WM-05). */
  set: OwnerSet | null;
  error?: string;
};

export type Me = { externalUserId: string; walletAddress: `0x${string}`; credentialId: string };

export type OwnerRow = {
  owner: OnChainOwner;
  credential?: RegistryCredential;
  isCurrent: boolean;
};

type Flow =
  | { type: 'add-passkey' }
  | { type: 'add-device' }
  | { type: 'add-address' }
  | { type: 'remove'; owner: OnChainOwner; credential?: RegistryCredential; isCurrent: boolean }
  | { type: 'claim' };

const log = (label: string, data?: unknown) => console.log(`[giano-wallet:manage] ${label}`, data ?? '');

export function Manage({ runtimes, config, onClose }: { runtimes: WalletRuntimes; config: WalletConfig; onClose?: () => void }) {
  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);
  const api: WalletManagementApi = useMemo(
    () => createWalletManagementApi({ apiUrl: config.walletApiUrl, getSessionToken: () => runtime.injection.getSessionToken() }),
    [config.walletApiUrl, runtime],
  );

  const [me, setMe] = useState<Me | null>(null);
  const [signedOut, setSignedOut] = useState(!runtime.injection.getSessionToken());
  const [credentials, setCredentials] = useState<RegistryCredential[]>([]);
  const [chainSets, setChainSets] = useState<ChainOwnerSet[]>([]);
  const [loading, setLoading] = useState(false);
  const [flow, setFlow] = useState<Flow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!runtime.injection.getSessionToken()) {
      setSignedOut(true);
      setMe(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const loadedMe = (await api.me()) as Me;
      setMe(loadedMe);
      setSignedOut(false);
      setCredentials(await api.listCredentials());
      const sets = await Promise.all(
        runtimes.servedChainIds.map(async (chainId): Promise<ChainOwnerSet> => {
          const chainRuntime = runtimes.runtimeFor(chainId);
          try {
            // WM-01: the owner set is read from the account contract, never the registry.
            const set = await readOwnerSet(chainRuntime.publicClient, loadedMe.walletAddress);
            return { chainId, chainName: chainRuntime.chainName, set };
          } catch (err) {
            // WM-05: "the chain could not be reached" is its own state — a user shown an
            // empty list would read it as fact.
            return { chainId, chainName: chainRuntime.chainName, set: null, error: (err as Error).message };
          }
        }),
      );
      setChainSets(sets);
      log('owner sets loaded', sets.map((row) => ({ chainId: row.chainId, deployed: row.set?.deployed, owners: row.set?.owners.length, error: row.error })));
    } catch (err) {
      const message = (err as Error).message;
      if (/401|session/i.test(message)) {
        setSignedOut(true);
        setMe(null);
      } else {
        setError(message);
        log('load failed', message);
      }
    } finally {
      setLoading(false);
    }
  }, [api, runtime, runtimes]);

  useEffect(() => {
    void load();
  }, [load]);

  // The set shown is the set ON THE CHAIN IT WAS READ FROM (WM-06): the first served
  // chain where the account is deployed and readable.
  const referenceSet = chainSets.find((row) => row.set?.deployed);
  const readableSets = chainSets.filter((row): row is ChainOwnerSet & { set: OwnerSet } => !!row.set);
  const unreadableSets = chainSets.filter((row) => row.set === null);
  const diverges = readableSets.some((a) => readableSets.some((b) => ownerSetsDiverge(a.set, b.set)));

  useEffect(() => {
    if (diverges) {
      // WM-06/WM-53: a set that differs between served chains is a problem to surface,
      // not a list to render quietly. The operator-side alert is owed by MC-37 tooling;
      // this is the user-facing half plus a console record.
      console.error(
        '[giano-wallet:manage] the owner set differs between served chains — needs reconciliation (MC-37)',
        readableSets.map((row) => ({ chainId: row.chainId, owners: row.set.owners.map((owner) => owner.fingerprint) })),
      );
    }
  }, [diverges, readableSets]);

  const rows: OwnerRow[] = useMemo(() => {
    if (!referenceSet?.set || !me) return [];
    const byOwnerBytes = new Map(
      credentials.map((credential) => [publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY).toLowerCase(), credential]),
    );
    return referenceSet.set.owners.map((owner) => {
      const credential = byOwnerBytes.get(owner.ownerBytes.toLowerCase());
      return {
        owner,
        credential,
        // WM-10: the credential the current session is using is marked wherever shown.
        isCurrent: !!credential && credential.credentialId === me.credentialId,
      };
    });
  }, [referenceSet, credentials, me]);

  /** Registry rows the chain does not back: shown as NOT owners, never omitted (WM-04). */
  const strayCredentials = useMemo(() => {
    if (!referenceSet?.set) return [];
    const onChain = new Set(referenceSet.set.owners.map((owner) => owner.ownerBytes.toLowerCase()));
    return credentials.filter(
      (credential) => !onChain.has(publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY).toLowerCase()),
    );
  }, [referenceSet, credentials]);

  const ownerCount = referenceSet?.set?.owners.length ?? 0;

  const signIn = async () => {
    setBusy(true);
    setError(null);
    try {
      await runtime.provider.request({ method: 'eth_requestAccounts' });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const signInExisting = async () => {
    setBusy(true);
    setError(null);
    try {
      // Discoverable sign-in: how a device uses a passkey it gained through a handoff.
      const result = await runtime.injection.signInWithExistingPasskey();
      log('signed in with existing passkey', { walletAddress: result.walletAddress });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const logout = async () => {
    setBusy(true);
    try {
      await runtime.injection.logout();
      setMe(null);
      setSignedOut(true);
      setChainSets([]);
      setCredentials([]);
    } finally {
      setBusy(false);
    }
  };

  // ── Signed out (WM-57): offer sign-in rather than failing ─────────────────────
  if (signedOut) {
    if (flow?.type === 'claim') {
      return (
        <ClaimFlow api={api} runtime={runtime} brand={config.branding.name} onBack={() => setFlow(null)} />
      );
    }
    return (
      <>
        <div className="card">
          <h2>Manage your wallet</h2>
          <p>Sign in to see and control the passkeys and accounts that can act on your wallet.</p>
          {error ? <div className="error" data-testid="manage-error">{error}</div> : null}
        </div>
        <div className="actions" style={{ flexDirection: 'column' }}>
          <button className="primary" onClick={signIn} disabled={busy} data-testid="manage-sign-in">
            {busy ? 'Waiting for passkey…' : 'Sign in with passkey'}
          </button>
          <button onClick={signInExisting} disabled={busy} data-testid="manage-sign-in-existing">
            Use a passkey created on another device
          </button>
          <button onClick={() => setFlow({ type: 'claim' })} disabled={busy} data-testid="manage-claim-entry">
            Add this device to an existing wallet
          </button>
          {onClose ? <button onClick={onClose}>Close</button> : null}
        </div>
      </>
    );
  }

  // ── Active flow ────────────────────────────────────────────────────────────────
  if (me && flow) {
    const done = async (refresh: boolean) => {
      setFlow(null);
      if (refresh) await load();
    };
    const flowProps = { api, runtimes, config, me, onDone: done };
    if (flow.type === 'add-passkey') return <AddPasskeyFlow {...flowProps} />;
    if (flow.type === 'add-device') return <AddDeviceFlow {...flowProps} />;
    if (flow.type === 'add-address') return <AddAddressFlow {...flowProps} />;
    if (flow.type === 'claim') return <ClaimFlow api={api} runtime={runtime} brand={config.branding.name} onBack={() => void done(false)} />;
    return (
      <RemoveFlow
        {...flowProps}
        owner={flow.owner}
        credential={flow.credential}
        isCurrent={flow.isCurrent}
        onSignedOut={async () => {
          // The server already revoked the session (WM-30) — drop the local token too.
          await runtime.injection.logout().catch(() => undefined);
          setFlow(null);
          setMe(null);
          setSignedOut(true);
          setChainSets([]);
          setCredentials([]);
        }}
      />
    );
  }

  // ── The set ────────────────────────────────────────────────────────────────────
  return (
    <>
      <div className="card">
        <h2>Wallet</h2>
        {me ? (
          <>
            <div className="kv">
              <span className="k">Address</span>
              <span className="v" data-testid="settings-address">{me.walletAddress}</span>
            </div>
            {chainSets.map((row) => (
              <div className="kv" key={row.chainId} data-testid={`settings-chain-${row.chainId}`}>
                <span className="k">
                  {row.chainName} ({row.chainId})
                </span>
                <span className="v">
                  {row.set === null ? 'unreachable' : row.set.deployed ? `deployed · ${row.set.owners.length} owner(s)` : 'deploys with your first transaction'}
                </span>
              </div>
            ))}
          </>
        ) : (
          <p>{loading ? 'Loading…' : 'No data yet.'}</p>
        )}
        {error ? <div className="error" data-testid="manage-error">{error}</div> : null}
      </div>

      {diverges ? (
        <div className="card" data-testid="manage-divergence">
          <h2>⚠ Owner sets differ between networks</h2>
          <p>
            The credentials that control this wallet are not the same on every network it is served on. This needs
            reconciliation — a change may not have reached every network yet. The list below is the set on{' '}
            {referenceSet?.chainName}.
          </p>
        </div>
      ) : null}

      {unreadableSets.length > 0 && !referenceSet ? (
        // WM-05: the set could not be read anywhere — say so; never render an empty list.
        <div className="card" data-testid="manage-unreadable">
          <h2>The owner set could not be read</h2>
          <p>
            None of the served networks could be reached, so what controls this wallet cannot be shown right now. This
            is a connectivity problem, not your credential list.
          </p>
          <div className="actions">
            <button onClick={() => void load()}>Try again</button>
          </div>
        </div>
      ) : null}

      {me && referenceSet?.set && (
        <div className="card">
          <h2>Who can act on this wallet</h2>
          {runtimes.servedChainIds.length > 1 ? (
            <p>As recorded on {referenceSet.chainName} — an owner change applies per network.</p>
          ) : null}
          {rows.map((row) => (
            <OwnerRowView
              key={row.owner.ownerBytes}
              row={row}
              api={api}
              canRemove={ownerCount > 1}
              onChanged={() => void load()}
              onRemove={() => setFlow({ type: 'remove', owner: row.owner, credential: row.credential, isCurrent: row.isCurrent })}
            />
          ))}
          {ownerCount === 1 ? (
            <p data-testid="manage-last-owner-note">
              This is the only credential that can act on the wallet, so it cannot be removed — removing it would lock
              the wallet forever. Add another passkey or account first.
            </p>
          ) : null}
          {strayCredentials.map((credential) => (
            <div className="kv" key={credential.credentialId} data-testid="manage-stray-credential">
              <span className="k">{credential.name ?? `${credential.credentialId.slice(0, 12)}…`}</span>
              <span className="v">{credential.removedAt ? 'removed — no longer an owner' : 'NOT an owner of this wallet'}</span>
            </div>
          ))}
        </div>
      )}

      {me && referenceSet?.set && !referenceSet.set.deployed ? (
        <div className="card">
          <p>The wallet is not deployed on any served network yet — owner management becomes available with its first transaction.</p>
        </div>
      ) : null}

      {me && (
        <div className="card">
          <h2>Add a credential</h2>
          <div className="actions" style={{ flexDirection: 'column', paddingTop: 4 }}>
            <button className="primary" onClick={() => setFlow({ type: 'add-passkey' })} data-testid="manage-add-passkey" disabled={!referenceSet?.set?.deployed}>
              Add a passkey on this device
            </button>
            <button onClick={() => setFlow({ type: 'add-device' })} data-testid="manage-add-device" disabled={!referenceSet?.set?.deployed}>
              Add a passkey on another device
            </button>
            <button onClick={() => setFlow({ type: 'add-address' })} data-testid="manage-add-address" disabled={!referenceSet?.set?.deployed}>
              Add an Ethereum account
            </button>
          </div>
        </div>
      )}

      <div className="actions">
        {onClose ? (
          <button onClick={onClose} data-testid="manage-close">
            Done
          </button>
        ) : (
          <button className="danger" onClick={logout} disabled={busy}>
            Log out (revoke session)
          </button>
        )}
      </div>
    </>
  );
}

function OwnerRowView({
  row,
  api,
  canRemove,
  onChanged,
  onRemove,
}: {
  row: OwnerRow;
  api: WalletManagementApi;
  canRemove: boolean;
  onChanged: () => void;
  onRemove: () => void;
}) {
  const { owner, credential, isCurrent } = row;
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(credential?.name ?? '');
  const [saving, setSaving] = useState(false);

  const saveName = async () => {
    if (!credential) return;
    setSaving(true);
    try {
      await api.renameCredential(credential.credentialId, name.trim() || null);
      log('credential renamed', { credentialId: credential.credentialId, name: name.trim() || null });
      setRenaming(false);
      onChanged();
    } catch (err) {
      console.error('[giano-wallet:manage] rename failed', err);
    } finally {
      setSaving(false);
    }
  };

  // WM-03/WM-09: identifiable without a name — kind, fingerprint, creation date, transports.
  const title = credential?.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey');
  const subtitle =
    owner.kind === 'address'
      ? owner.address
      : credential
        ? `passkey · added ${new Date(credential.createdAt).toLocaleDateString()}${credential.transports?.length ? ` · ${credential.transports.join('/')}` : ''}`
        : 'passkey · added outside this deployment'; // WM-04: never silently omitted

  return (
    <div style={{ borderBottom: '1px dashed var(--border)', padding: '8px 0' }} data-testid="manage-owner-row" data-fingerprint={owner.fingerprint}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'baseline' }}>
        <div>
          <b data-testid="manage-owner-name">{title}</b>{' '}
          {isCurrent ? (
            <span style={{ background: 'var(--pill)', borderRadius: 6, padding: '1px 6px', fontSize: 11 }} data-testid="manage-owner-current">
              this session
            </span>
          ) : null}
          <div style={{ color: 'var(--muted)', fontSize: 12, wordBreak: 'break-all' }}>{subtitle}</div>
        </div>
        <span className="v" style={{ fontFamily: 'ui-monospace, monospace', fontSize: 13 }} data-testid="manage-owner-fingerprint">
          {owner.fingerprint}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
        {credential ? (
          renaming ? (
            <>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Name this credential"
                style={{ flex: 1, borderRadius: 8, border: '1px solid var(--border)', padding: '6px 8px', background: 'var(--bg)', color: 'var(--fg)' }}
                data-testid="manage-rename-input"
              />
              <button style={{ flex: 'none', padding: '6px 10px', fontSize: 13 }} onClick={() => void saveName()} disabled={saving} data-testid="manage-rename-save">
                Save
              </button>
            </>
          ) : (
            <button style={{ flex: 'none', padding: '6px 10px', fontSize: 13 }} onClick={() => setRenaming(true)} data-testid="manage-rename">
              Rename
            </button>
          )
        ) : null}
        <button
          style={{ flex: 'none', padding: '6px 10px', fontSize: 13 }}
          className="danger"
          onClick={onRemove}
          disabled={!canRemove}
          title={canRemove ? undefined : 'The last remaining credential cannot be removed'}
          data-testid="manage-remove"
        >
          Remove
        </button>
      </div>
    </div>
  );
}
