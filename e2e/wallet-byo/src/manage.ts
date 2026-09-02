import {
  ChainType,
  createWalletManagementApi,
  depositPasskeyIntoPendingAddition,
  encodeAddOwnerPublicKey,
  encodeRemoveOwnerAtIndex,
  publicKeyOwnerBytes,
  readOwnerSet,
  type OnChainOwner,
  type RegistryCredential,
  type WalletManagementApi,
} from '@appliedblockchain/giano-wallet-core';
import type { Hex } from 'viem';
import { CONFIG } from './config';
import type { WalletRuntime } from './runtime';

/**
 * Bring-your-own-UI wallet management (WM-60, WM-61): viewing, adding and removing
 * credentials, implemented against exactly the same API the stock interface uses — no
 * Giano-specific privilege, plain DOM instead of React, deliberately different labels so
 * the e2e suite can prove which UI ran the flow.
 */

type Runtimes = { runtimeFor: (chainId: number) => WalletRuntime; servedChainIds: number[] };

type Me = { externalUserId: string; walletAddress: `0x${string}`; credentialId: string };

const log = (label: string, data?: unknown) => console.log(`[giano-byo:manage] ${label}`, data ?? '');

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { dataset?: Record<string, string> } = {},
  ...children: (Node | string)[]
) {
  const node = document.createElement(tag);
  const { dataset, ...rest } = props;
  Object.assign(node, rest);
  if (dataset) for (const [key, value] of Object.entries(dataset)) node.dataset[key] = value;
  node.append(...children);
  return node;
}

async function ensureAccount(runtime: WalletRuntime): Promise<boolean> {
  if (runtime.provider.getSmartAccount()) return true;
  await runtime.provider.request({ method: 'giano_restoreAccount', params: [] } as never).catch(() => undefined);
  return !!runtime.provider.getSmartAccount();
}

type ChainReport = { chainId: number; chainName: string; state: string; detail?: string };

/**
 * Applies one owner change per served chain — chain-bound self-calls, sponsored under the
 * platform wallet-management rule, sponsorship pre-flighted before any passkey prompt
 * (WM-68), undeployed chains skipped with a statement (WM-46). The BYO port of the same
 * obligations the stock wallet carries; per-chain progress is reported as it happens
 * (WM-44).
 */
async function applyPerChain(
  runtimes: Runtimes,
  wallet: `0x${string}`,
  buildData: (runtime: WalletRuntime) => Promise<Hex | null>,
  onReport: (rows: ChainReport[]) => void,
): Promise<{ ok: boolean; applied: number[]; refusedReason?: string; rows: ChainReport[] }> {
  const rows: ChainReport[] = runtimes.servedChainIds.map((chainId) => ({
    chainId,
    chainName: runtimes.runtimeFor(chainId).chainName,
    state: 'waiting',
  }));
  const set = (chainId: number, state: string, detail?: string) => {
    const row = rows.find((entry) => entry.chainId === chainId)!;
    row.state = state;
    row.detail = detail;
    onReport([...rows]);
  };

  const applied: number[] = [];
  let refusedReason: string | undefined;
  for (const chainId of runtimes.servedChainIds) {
    const runtime = runtimes.runtimeFor(chainId);
    if (refusedReason) {
      set(chainId, 'refused', 'not attempted — sponsorship was refused');
      continue;
    }
    try {
      if (!(await ensureAccount(runtime))) {
        set(chainId, 'failed', 'no signed-in account');
        continue;
      }
      const code = await runtime.publicClient.getCode({ address: wallet }).catch(() => undefined);
      if (!code || code === '0x') {
        set(chainId, 'skipped', 'wallet not deployed on this network yet — not applied here');
        continue;
      }
      const data = await buildData(runtime);
      if (data === null) {
        set(chainId, 'skipped', 'nothing to change on this network');
        continue;
      }
      const preflight = await runtime.checkSponsorship({ to: wallet, data });
      if (preflight.state === 'refused') {
        refusedReason = preflight.reason;
        set(chainId, 'refused', `${preflight.reason}: ${preflight.message}`);
        log('sponsorship refused', preflight);
        continue;
      }
      if (preflight.state === 'unavailable') {
        set(chainId, 'failed', `sponsorship unavailable: ${preflight.message}`);
        continue;
      }
      set(chainId, 'submitting');
      const hash = await runtime.provider.request({
        method: 'eth_sendTransaction',
        params: [{ to: wallet, value: '0x0', data } as never],
      });
      set(chainId, 'submitted');
      const receipt = (await runtime.provider.request({ method: 'waitForUserOperationReceipt', params: [hash as `0x${string}`] })) as {
        success: boolean;
      };
      if (receipt.success) {
        applied.push(chainId);
        set(chainId, 'confirmed');
      } else {
        set(chainId, 'failed', 'reverted on-chain');
      }
    } catch (error) {
      set(chainId, 'failed', (error as Error).message);
    }
  }
  const ok = !refusedReason && applied.length > 0 && rows.every((row) => row.state === 'confirmed' || row.state === 'skipped');
  log('owner change outcome', { ok, applied, rows });
  return { ok, applied, refusedReason, rows };
}

export function renderManage(root: HTMLElement, options: { runtimes: Runtimes; onClose?: () => void }): void {
  const { runtimes, onClose } = options;
  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);
  const api: WalletManagementApi = createWalletManagementApi({
    apiUrl: CONFIG.walletApiUrl,
    getSessionToken: () => runtime.injection.getSessionToken(),
  });

  type Flow =
    | { type: 'add'; stage: 'consent' | 'running' | 'done'; slotId?: string; fingerprint?: string; publicKey?: { x: Hex; y: Hex }; rows?: ChainReport[]; ok?: boolean; message?: string }
    | { type: 'remove'; stage: 'consent' | 'running' | 'done'; owner: OnChainOwner; credential?: RegistryCredential; isCurrent: boolean; rows?: ChainReport[]; ok?: boolean; endedSession?: boolean; message?: string };

  let me: Me | null = null;
  let credentials: RegistryCredential[] = [];
  let owners: OnChainOwner[] | null = null;
  let setError: string | null = null;
  let flow: Flow | null = null;
  let busy = false;
  let error: string | null = null;

  const rerender = () => render();

  const load = async () => {
    if (!runtime.injection.getSessionToken()) {
      me = null;
      rerender();
      return;
    }
    try {
      me = (await api.me()) as Me;
      credentials = await api.listCredentials();
      try {
        // WM-01/WM-02: the chain IS the owner set; read from the first served chain.
        const set = await readOwnerSet(runtime.publicClient, me.walletAddress);
        owners = set.deployed ? set.owners : [];
        setError = null;
      } catch (err) {
        // WM-05: an unreadable chain is its own state, never an empty list.
        owners = null;
        setError = (err as Error).message;
      }
      log('loaded', { wallet: me.walletAddress, owners: owners?.length, credentials: credentials.length });
    } catch (err) {
      if ((err as { status?: number }).status === 401) me = null;
      else error = (err as Error).message;
    }
    rerender();
  };

  const startAdd = async () => {
    flow = { type: 'add', stage: 'consent' };
    busy = true;
    rerender();
    try {
      const slot = await api.openPendingAddition();
      const userId = await runtime.injection.encodeUserId(crypto.randomUUID().replace(/-/g, ''), runtime.factoryAddress, ChainType.EVM);
      const deposited = await depositPasskeyIntoPendingAddition({ api, claimCode: slot.claimCode, userId, userName: CONFIG.brandName });
      flow = { type: 'add', stage: 'consent', slotId: slot.id, fingerprint: deposited.fingerprint, publicKey: deposited.publicKey };
      log('passkey deposited', { fingerprint: deposited.fingerprint });
    } catch (err) {
      flow = { type: 'add', stage: 'done', ok: false, message: (err as Error).message };
      log('add failed', (err as Error).message);
    } finally {
      busy = false;
      rerender();
    }
  };

  const approveAdd = async (slotId: string, publicKey: { x: Hex; y: Hex }) => {
    flow = { type: 'add', stage: 'running', slotId, publicKey, rows: [] };
    rerender();
    const outcome = await applyPerChain(
      runtimes,
      me!.walletAddress,
      async () => encodeAddOwnerPublicKey(publicKey.x, publicKey.y),
      (rows) => {
        if (flow?.type === 'add') {
          flow.rows = rows;
          rerender();
        }
      },
    );
    if (outcome.applied.length > 0) {
      // Chain first, registry second (WM-15): bind only what the chain confirmed.
      await api
        .completePendingAddition(slotId, { chainIds: outcome.applied, name: `BYO backup · ${new Date().toLocaleDateString()}` })
        .catch((err) => log('binding failed after on-chain success (WM-04 shows it honestly)', (err as Error).message));
    }
    flow = { type: 'add', stage: 'done', ok: outcome.ok, rows: outcome.rows, message: outcome.refusedReason };
    rerender();
  };

  const approveRemove = async (state: Extract<Flow, { type: 'remove' }>) => {
    flow = { ...state, stage: 'running', rows: [] };
    rerender();
    const outcome = await applyPerChain(
      runtimes,
      me!.walletAddress,
      async (chainRuntime) => {
        // WM-29: re-read the index from THIS chain immediately before constructing.
        const set = await readOwnerSet(chainRuntime.publicClient, me!.walletAddress);
        const found = set.owners.find((candidate) => candidate.ownerBytes.toLowerCase() === state.owner.ownerBytes.toLowerCase());
        if (!found) return null;
        if (set.owners.length === 1) throw new Error('last owner on this network — removal refused');
        return encodeRemoveOwnerAtIndex(found.index, found.ownerBytes);
      },
      (rows) => {
        if (flow?.type === 'remove') {
          flow.rows = rows;
          rerender();
        }
      },
    );
    let endedSession = false;
    if (outcome.applied.length > 0 && state.credential) {
      try {
        const marked = await api.markCredentialRemoved(state.credential.credentialId);
        endedSession = marked.removedCurrentSession;
      } catch (err) {
        log('registry mark failed — the chain change stands', (err as Error).message);
      }
    }
    if (endedSession) {
      await runtime.injection.logout().catch(() => undefined);
    }
    flow = { ...state, stage: 'done', rows: outcome.rows, ok: outcome.ok, endedSession, message: outcome.refusedReason };
    rerender();
  };

  const progressList = (rows: ChainReport[] | undefined) =>
    el(
      'div',
      { dataset: { testid: 'byo-manage-progress' } },
      ...(rows ?? []).map((row) =>
        el(
          'div',
          { className: 'origin', dataset: { testid: `byo-manage-progress-${row.chainId}`, state: row.state } },
          `${row.chainName} (${row.chainId}): ${row.state}${row.detail ? ` — ${row.detail}` : ''}`,
        ),
      ),
    );

  function render(): void {
    root.replaceChildren();

    // Signed out (WM-57): offer sign-in rather than failing.
    if (!me) {
      root.append(
        el('h2', {}, 'Wallet keys'),
        el('div', { className: 'idle' }, 'Unlock your BYO wallet to see and change what can act on it.'),
        error ? el('div', { className: 'payload', dataset: { testid: 'byo-manage-error' } }, error) : '',
        el(
          'div',
          { className: 'row' },
          onClose ? el('button', { className: 'secondary', textContent: 'Close', onclick: () => onClose() }) : '',
          el('button', {
            textContent: busy ? 'Waiting for passkey…' : 'Unlock with passkey',
            disabled: busy,
            dataset: { testid: 'byo-manage-unlock' },
            onclick: async () => {
              busy = true;
              error = null;
              rerender();
              try {
                await runtime.provider.request({ method: 'eth_requestAccounts' });
                await load();
              } catch (err) {
                error = (err as Error).message;
              } finally {
                busy = false;
                rerender();
              }
            },
          }),
        ),
      );
      return;
    }

    // Active flow.
    if (flow) {
      if (flow.type === 'add') {
        if (flow.stage === 'consent') {
          root.append(
            el('h2', {}, 'Add a key to this wallet'),
            flow.fingerprint
              ? el('div', {}, el('div', { className: 'idle' }, 'A new passkey was created on this device. Its fingerprint:'), el('pre', { className: 'payload', dataset: { testid: 'byo-manage-fingerprint' } }, flow.fingerprint))
              : el('div', { className: 'idle' }, busy ? 'Creating the passkey…' : 'Preparing…'),
            el(
              'div',
              { className: 'row' },
              el('button', {
                className: 'secondary',
                textContent: 'Abort',
                onclick: async () => {
                  if (flow?.type === 'add' && flow.slotId) await api.declinePendingAddition(flow.slotId).catch(() => undefined);
                  flow = null;
                  rerender();
                },
              }),
              flow.slotId && flow.publicKey
                ? el('button', {
                    textContent: 'Make it an owner',
                    dataset: { testid: 'byo-manage-add-approve' },
                    onclick: () => void approveAdd(flow!.type === 'add' ? flow!.slotId! : '', (flow as Extract<Flow, { type: 'add' }>).publicKey!),
                  })
                : '',
            ),
          );
          return;
        }
        root.append(
          el('h2', {}, flow.stage === 'running' ? 'Adding the key…' : flow.ok ? 'Key added' : 'Key not fully added'),
          progressList(flow.rows),
          flow.message ? el('div', { className: 'payload' }, flow.message) : '',
          flow.stage === 'done'
            ? el('div', { className: 'row' }, el('button', { textContent: 'Back to keys', dataset: { testid: 'byo-manage-flow-done' }, onclick: () => { flow = null; void load(); } }))
            : '',
        );
        return;
      }

      // remove
      if (flow.stage === 'consent') {
        const state = flow;
        root.append(
          el('h2', {}, 'Remove this key?'),
          // WM-32: identified by more than a name.
          el('div', { className: 'idle' }, `${state.credential?.name ?? (state.owner.kind === 'address' ? 'Ethereum account' : 'Passkey')} · fingerprint ${state.owner.fingerprint}`),
          el('pre', { className: 'payload', dataset: { testid: 'byo-manage-remove-identifier' } }, state.owner.kind === 'address' ? (state.owner.address as string) : state.owner.ownerBytes),
          state.isCurrent
            ? el('div', { className: 'payload', dataset: { testid: 'byo-manage-remove-current' } }, 'This is the key this session is using — removing it signs you out here (WM-30).')
            : '',
          el(
            'div',
            { className: 'row' },
            el('button', { className: 'secondary', textContent: 'Keep it', onclick: () => { flow = null; rerender(); } }),
            el('button', { textContent: 'Remove it', dataset: { testid: 'byo-manage-remove-approve' }, onclick: () => void approveRemove(state) }),
          ),
        );
        return;
      }
      root.append(
        el('h2', {}, flow.stage === 'running' ? 'Removing…' : flow.ok ? 'Key removed' : 'Key not fully removed'),
        progressList(flow.rows),
        flow.message ? el('div', { className: 'payload' }, flow.message) : '',
        flow.endedSession ? el('div', { className: 'payload', dataset: { testid: 'byo-manage-signed-out' } }, 'That was this session’s key — you are signed out.') : '',
        flow.stage === 'done'
          ? el(
              'div',
              { className: 'row' },
              el('button', {
                textContent: flow.endedSession ? 'OK' : 'Back to keys',
                dataset: { testid: 'byo-manage-flow-done' },
                onclick: () => {
                  const ended = flow?.type === 'remove' && flow.endedSession;
                  flow = null;
                  if (ended) {
                    me = null;
                    rerender();
                  } else void load();
                },
              }),
            )
          : '',
      );
      return;
    }

    // The set.
    const byOwnerBytes = new Map(credentials.map((credential) => [publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY).toLowerCase(), credential]));
    const children: (Node | string)[] = [el('h2', {}, 'Wallet keys')];
    children.push(el('div', { className: 'origin', dataset: { testid: 'byo-manage-address' } }, me.walletAddress));

    if (owners === null) {
      // WM-05: say the chain could not be read — never render an empty set as fact.
      children.push(
        el('div', { className: 'payload', dataset: { testid: 'byo-manage-unreadable' } }, `The network could not be read, so the key list cannot be shown: ${setError ?? 'unknown error'}`),
        el('div', { className: 'row' }, el('button', { textContent: 'Retry', onclick: () => void load() })),
      );
    } else {
      for (const owner of owners) {
        const credential = byOwnerBytes.get(owner.ownerBytes.toLowerCase());
        const isCurrent = !!credential && credential.credentialId === me.credentialId;
        children.push(
          el(
            'div',
            { className: 'origin', dataset: { testid: 'byo-manage-owner', fingerprint: owner.fingerprint } },
            el('b', {}, credential?.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey (added elsewhere)')),
            ` · ${owner.fingerprint}`,
            isCurrent ? el('span', { dataset: { testid: 'byo-manage-owner-current' } }, ' · this session') : '',
            el('button', {
              className: 'secondary',
              textContent: 'Remove',
              disabled: owners!.length <= 1,
              dataset: { testid: 'byo-manage-remove' },
              onclick: () => {
                flow = { type: 'remove', stage: 'consent', owner, credential, isCurrent };
                rerender();
              },
            }),
          ),
        );
      }
      if (owners.length === 1) {
        children.push(
          el('div', { className: 'idle', dataset: { testid: 'byo-manage-last-owner' } }, 'Your only key cannot be removed — that would lock the wallet forever. Add another key first.'),
        );
      }
      // WM-04: registry rows the chain does not back are shown as NOT owners.
      for (const credential of credentials) {
        if (!owners.some((owner) => owner.ownerBytes.toLowerCase() === publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY).toLowerCase())) {
          children.push(
            el(
              'div',
              { className: 'origin', dataset: { testid: 'byo-manage-stray' } },
              `${credential.name ?? credential.credentialId.slice(0, 12)} · ${credential.removedAt ? 'removed — no longer an owner' : 'NOT an owner of this wallet'}`,
            ),
          );
        }
      }
      children.push(
        el(
          'div',
          { className: 'row' },
          el('button', { textContent: 'Add a key on this device', dataset: { testid: 'byo-manage-add' }, onclick: () => void startAdd() }),
        ),
      );
    }

    if (onClose) {
      children.push(el('div', { className: 'row' }, el('button', { className: 'secondary', textContent: 'Close', dataset: { testid: 'byo-manage-close' }, onclick: () => onClose() })));
    }
    root.append(...children);
  }

  void load();
  render();
}
