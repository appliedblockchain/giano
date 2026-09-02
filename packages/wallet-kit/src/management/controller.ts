import {
  ChainType,
  createWalletManagementApi,
  depositPasskeyIntoPendingAddition,
  encodeAddOwnerAddress,
  encodeAddOwnerPublicKey,
  encodeRemoveOwnerAtIndex,
  ownerFingerprint,
  ownerSetsDiverge,
  publicKeyOwnerBytes,
  readOwnerSet,
  type OwnerSet,
  type RegistryCredential,
  type SponsorshipRefusalReason,
  type WalletManagementApi,
} from '@appliedblockchain/giano-wallet-core';
import { getAddress, isAddress, type Address, type Hex } from 'viem';
import type { WalletConfig } from '../config';
import type { SponsorshipPreflight, WalletRuntimes } from '../runtimes';
import { applyOwnerChange, type ChainProgress } from './apply-owner-change';
import { preflightManagement } from './preflight';

/**
 * The headless wallet-management controller (WK-16): drives the whole of
 * WALLET-MANAGEMENT-REQUIREMENTS §4 — viewing the owner set, naming, adding on this
 * device, adding from a second device, adding an externally-owned account, removal, and
 * the new device's claim — emitting state and accepting user actions, so the view is
 * pure rendering.
 *
 * The ordering invariants live HERE, not in any view (WK-18, D6): the owner set is read
 * from the chain and joined to the registry by owner bytes (WM-01/WM-02); the chain is
 * written before the registry binds (WM-15); the removal index is re-read per chain
 * immediately before use (WM-29); the cross-device fingerprint is recomputed from the key
 * as received (WM-20); and there is no construction that reaches `removeLastOwner` (WM-28,
 * WK-19).
 */

export type SponsorshipRefusal = Extract<SponsorshipPreflight, { state: 'refused' }>;

export type OwnerRow = {
  kind: 'passkey' | 'address';
  /** Stable, human-comparable id derived from the owner bytes (WM-03). */
  fingerprint: string;
  /** The owner's canonical on-chain encoding — what owners are matched by (WM-02). */
  ownerBytes: Hex;
  /** Set for kind 'address'. */
  address?: Address;
  /** The user-set name, when the registry has a row for this owner. */
  name: string | null;
  /** The registry row's id, when there is one — what rename() takes. Null for address owners. */
  credentialId: string | null;
  /** True for the credential the current session uses (WM-10). */
  isCurrent: boolean;
  createdAt: string | null;
  transports: string[] | null;
  /** Present when the registry shows it removed but the chain still lists it, or vice-versa. */
  removedAt: string | null;
};

export type ManagementChainStatus = {
  chainId: number;
  chainName: string;
  /** null = the chain could not be read — its own state, never "not deployed" (WM-05). */
  deployed: boolean | null;
  /** Owner count on this chain; null when the chain could not be read. */
  owners: number | null;
  error?: string;
};

export type ManagementState = {
  view: 'signed-out' | 'loading' | 'set' | 'unreadable' | 'flow';
  walletAddress: Hex | null;
  /** The owner set read from the reference chain, joined to the registry by owner bytes. */
  owners: OwnerRow[];
  /** Registry rows the chain does not back — shown as NOT owners, never omitted (WM-04). */
  strays: OwnerRow[];
  /** True when served chains disagree on the owner set — a problem, not a list (WM-06). */
  divergent: boolean;
  /** Per-chain deployment/readability, so the client can say "unreachable" vs "one credential". */
  chains: ManagementChainStatus[];
  /** The chain the rendered set was read from — named when more than one chain is served. */
  referenceChainName: string | null;
  /** True when the account has code on at least one served chain — owner changes need it. */
  deployed: boolean;
  busy: boolean;
  error: string | null;
};

export type AddressInputError = 'invalid-address' | 'not-checksummed' | 'own-wallet';

export type ManagementFlow =
  // add on this device / from a second device
  | { type: 'add'; step: 'preparing' }
  | { type: 'add'; step: 'claim-code'; claimCode: string; expiresAt: string; cancel: () => void } // show on device A
  | {
      type: 'add';
      step: 'confirm-fingerprint'; // compare on both screens
      fingerprint: string;
      name: string;
      setName: (name: string) => void;
      approve: () => void;
      decline: () => void;
    }
  | { type: 'add'; step: 'applying'; chains: ChainProgress[] } // per-chain progress (WM-44)
  | { type: 'add'; step: 'done'; ok: boolean; chains: ChainProgress[]; appliedChainIds: number[]; refusal?: SponsorshipRefusal }
  | { type: 'add'; step: 'declined' }
  | { type: 'add'; step: 'expired' }
  | { type: 'add'; step: 'error'; message: string }

  // add an externally-owned account
  | { type: 'address'; step: 'preparing' }
  | { type: 'address'; step: 'input'; value: string; setAddress: (value: string) => void; error: AddressInputError | null; continue: () => void }
  | {
      type: 'address';
      step: 'confirm';
      address: Address; // full, unabbreviated (WM-25)
      grantNotice: string; // "full and equal control" (WM-26)
      acknowledged: boolean;
      acknowledge: (value: boolean) => void;
      approve: () => void;
      back: () => void;
    }
  | { type: 'address'; step: 'applying'; chains: ChainProgress[] }
  | { type: 'address'; step: 'done'; ok: boolean; chains: ChainProgress[]; appliedChainIds: number[]; refusal?: SponsorshipRefusal }
  | { type: 'address'; step: 'error'; message: string }

  // remove
  | { type: 'remove'; step: 'confirm'; owner: OwnerRow; endsThisSession: boolean; approve: () => void; cancel: () => void }
  | { type: 'remove'; step: 'applying'; chains: ChainProgress[] }
  | {
      type: 'remove';
      step: 'done';
      ok: boolean;
      endedSession: boolean;
      chains: ChainProgress[];
      appliedChainIds: number[];
      refusal?: SponsorshipRefusal;
    }
  | { type: 'remove'; step: 'error'; message: string }

  // the new device claiming a code (needs no session — the code routes, WM-19)
  | { type: 'claim'; step: 'input'; code: string; setCode: (value: string) => void; submit: () => void }
  | { type: 'claim'; step: 'depositing' }
  | { type: 'claim'; step: 'deposited'; fingerprint: string } // now compare on device A
  | { type: 'claim'; step: 'error'; code: string; message: string; retry: () => void } // actionable, distinct from a network error

  // a sponsorship refusal met before any passkey prompt (WM-48, WM-49, WK-13)
  | { type: 'refused'; reason: SponsorshipRefusalReason; message: string; back: () => void };

export type ManagementController = {
  readonly state: ManagementState;
  readonly flow: ManagementFlow | null;
  subscribe: (listener: (state: ManagementState) => void) => () => void;
  load: () => Promise<void>;

  // ── sign-in (WM-57) ──
  signIn: () => Promise<void>; // create-or-use a passkey on this device
  signInWithExistingPasskey: () => Promise<void>; // discoverable: a device handed a credential via handoff
  logout: () => Promise<void>;

  // ── the set ──
  rename: (credentialId: string, name: string | null) => Promise<void>;

  // ── start a flow (each drives its own sub-state through `flow`) ──
  startAddThisDevice: () => void; // WM-14
  startAddSecondDevice: () => void; // WM-18…WM-23
  startAddAddress: () => void; // WM-24…WM-26
  startRemove: (owner: OwnerRow) => void; // WM-27…WM-32
  startClaimOnThisDevice: () => void; // the NEW device's side of a handoff

  /** Leaves the active flow: declines an abandoned slot, reloads when the flow changed the set. */
  dismissFlow: () => void;
  /** Stops timers and drops listeners (idempotent — a remount may subscribe again). */
  destroy: () => void;
};

export type CreateManagementControllerOptions = {
  runtimes: WalletRuntimes;
  config: Pick<WalletConfig, 'walletApiUrl' | 'branding'>;
  /** How often the authorising device polls an open handoff slot (D8 phase 5). */
  pollIntervalMs?: number;
  /** Testing seams only — never set in production code. */
  internals?: {
    api?: WalletManagementApi;
    depositPasskey?: typeof depositPasskeyIntoPendingAddition;
  };
};

type Me = { externalUserId: string; walletAddress: Hex; credentialId: string };

type ChainOwnerSet = {
  chainId: number;
  chainName: string;
  /** null = the chain could not be read — its own state, never an empty list (WM-05). */
  set: OwnerSet | null;
  error?: string;
};

const log = (label: string, data?: unknown) => console.log(`[giano-wallet-kit:manage] ${label}`, data ?? '');

/** WM-26: what an added account is granted, stated plainly. Tenants may word their own. */
const GRANT_NOTICE =
  'This account gains full and equal control of your wallet — no threshold, no limit. ' +
  "It can also act directly on-chain, outside the app's relay: those transactions are not covered by the relay's " +
  'policy checks or its audit trail, and it pays its own gas for them.';

export function createManagementController({ runtimes, config, pollIntervalMs = 2000, internals }: CreateManagementControllerOptions): ManagementController {
  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);
  const api =
    internals?.api ?? createWalletManagementApi({ apiUrl: config.walletApiUrl, getSessionToken: () => runtime.injection.getSessionToken() });
  const deposit = internals?.depositPasskey ?? depositPasskeyIntoPendingAddition;

  let me: Me | null = null;
  let credentials: RegistryCredential[] = [];
  let chainSets: ChainOwnerSet[] = [];
  let signedOut = !runtime.injection.getSessionToken();
  let loadedOnce = false;
  let loading = false;
  let busy = false;
  let error: string | null = null;
  let flow: ManagementFlow | null = null;
  /** True once the active flow changed the wallet — dismissing it reloads the set. */
  let flowDirty = false;
  /** The removal ended this session — resolved into signed-out when the flow is dismissed. */
  let pendingEndedSession = false;
  /** The open pending-addition slot, declined if the flow is abandoned before it settles. */
  let activeSlot: { id: string; settled: boolean } | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  const listeners = new Set<(state: ManagementState) => void>();
  let state = computeState();

  function notify() {
    state = computeState();
    listeners.forEach((listener) => listener(state));
  }

  function setFlow(next: ManagementFlow | null) {
    flow = next;
    notify();
  }

  /**
   * Guards a flow's async continuations: a preflight, slot open or passkey deposit that
   * resolves after the user dismissed the flow (or started another) must not resurrect it.
   * Every flow start takes a new generation; dismissing bumps it.
   */
  let flowGeneration = 0;
  function setFlowIf(generation: number, next: ManagementFlow | null) {
    if (generation === flowGeneration) setFlow(next);
  }

  function computeState(): ManagementState {
    const readable = chainSets.filter((row): row is ChainOwnerSet & { set: OwnerSet } => row.set !== null);
    // The set shown is the set ON THE CHAIN IT WAS READ FROM (WM-06): the first served
    // chain where the account is deployed and readable, else the first readable one.
    const referenceSet = readable.find((row) => row.set.deployed) ?? readable[0] ?? null;
    const divergent = readable.some((a) => readable.some((b) => ownerSetsDiverge(a.set, b.set)));

    const byOwnerBytes = new Map(
      credentials.map((credential) => [publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY).toLowerCase(), credential]),
    );
    const owners: OwnerRow[] = (referenceSet?.set.owners ?? []).map((owner) => {
      const credential = byOwnerBytes.get(owner.ownerBytes.toLowerCase());
      return {
        kind: owner.kind,
        fingerprint: owner.fingerprint,
        ownerBytes: owner.ownerBytes,
        address: owner.address,
        name: credential?.name ?? null,
        credentialId: credential?.credentialId ?? null,
        // WM-10: the credential the current session is using is marked wherever shown.
        isCurrent: !!credential && !!me && credential.credentialId === me.credentialId,
        createdAt: credential?.createdAt ?? null,
        transports: credential?.transports ?? null,
        removedAt: credential?.removedAt ?? null,
      };
    });

    // WM-04: registry rows the chain does not back are shown as NOT owners, never omitted.
    const onChain = new Set((referenceSet?.set.owners ?? []).map((owner) => owner.ownerBytes.toLowerCase()));
    const strays: OwnerRow[] = referenceSet
      ? credentials
          .filter((credential) => !onChain.has(publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY).toLowerCase()))
          .map((credential) => {
            const ownerBytes = publicKeyOwnerBytes(credential.publicKeyX, credential.publicKeyY);
            return {
              kind: 'passkey' as const,
              fingerprint: ownerFingerprint(ownerBytes),
              ownerBytes,
              name: credential.name,
              credentialId: credential.credentialId,
              isCurrent: !!me && credential.credentialId === me.credentialId,
              createdAt: credential.createdAt,
              transports: credential.transports,
              removedAt: credential.removedAt,
            };
          })
      : [];

    const view: ManagementState['view'] = flow
      ? 'flow'
      : signedOut
        ? 'signed-out'
        : loading && !loadedOnce
          ? 'loading'
          : loadedOnce && chainSets.length > 0 && readable.length === 0
            ? 'unreadable' // WM-05: the set could not be read anywhere — its own state, never an empty list
            : 'set';

    return {
      view,
      walletAddress: me?.walletAddress ?? null,
      owners,
      strays,
      divergent,
      chains: chainSets.map((row) => ({
        chainId: row.chainId,
        chainName: row.chainName,
        deployed: row.set === null ? null : row.set.deployed,
        owners: row.set === null ? null : row.set.owners.length,
        error: row.error,
      })),
      referenceChainName: referenceSet?.chainName ?? null,
      deployed: readable.some((row) => row.set.deployed),
      busy,
      error,
    };
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function resetToSignedOut() {
    me = null;
    signedOut = true;
    credentials = [];
    chainSets = [];
    loadedOnce = false;
  }

  async function load(): Promise<void> {
    if (!runtime.injection.getSessionToken()) {
      resetToSignedOut();
      notify();
      return;
    }
    loading = true;
    error = null;
    notify();
    try {
      me = (await api.me()) as Me;
      signedOut = false;
      credentials = await api.listCredentials();
      chainSets = await Promise.all(
        runtimes.servedChainIds.map(async (chainId): Promise<ChainOwnerSet> => {
          const chainRuntime = runtimes.runtimeFor(chainId);
          try {
            // WM-01: the owner set is read from the account contract, never the registry (WK-17).
            const set = await readOwnerSet(chainRuntime.publicClient, me!.walletAddress);
            return { chainId, chainName: chainRuntime.chainName, set };
          } catch (err) {
            // WM-05: "the chain could not be reached" is its own state — a user shown an
            // empty list would read it as fact.
            return { chainId, chainName: chainRuntime.chainName, set: null, error: (err as Error).message };
          }
        }),
      );
      loadedOnce = true;
      log(
        'owner sets loaded',
        chainSets.map((row) => ({ chainId: row.chainId, deployed: row.set?.deployed, owners: row.set?.owners.length, error: row.error })),
      );
      const readable = chainSets.filter((row): row is ChainOwnerSet & { set: OwnerSet } => row.set !== null);
      if (readable.some((a) => readable.some((b) => ownerSetsDiverge(a.set, b.set)))) {
        // WM-06/WM-53: a set that differs between served chains is a problem to surface,
        // not a list to render quietly. The operator-side alert is owed by MC-37 tooling;
        // this is the console record backing the user-facing half.
        console.error(
          '[giano-wallet-kit:manage] the owner set differs between served chains — needs reconciliation (MC-37)',
          readable.map((row) => ({ chainId: row.chainId, owners: row.set.owners.map((owner) => owner.fingerprint) })),
        );
      }
    } catch (err) {
      const message = (err as Error).message;
      const status = (err as { status?: number }).status;
      if (status === 401 || /401|session/i.test(message)) {
        resetToSignedOut();
      } else {
        error = message;
        log('load failed', message);
      }
    } finally {
      loading = false;
      notify();
    }
  }

  async function withBusy(action: () => Promise<void>): Promise<void> {
    busy = true;
    error = null;
    notify();
    try {
      await action();
    } catch (err) {
      error = (err as Error).message;
      log('action failed', error);
    } finally {
      busy = false;
      notify();
    }
  }

  const refusedFlow = (refusal: SponsorshipRefusal): ManagementFlow => ({
    type: 'refused',
    reason: refusal.reason,
    message: refusal.message,
    back: () => dismissFlow(),
  });

  // ── the add flows (WM-14, WM-18…WM-23) ──────────────────────────────────────────

  function startAdd(mode: 'this-device' | 'second-device') {
    if (!me || flow) return;
    const wallet = me.walletAddress;
    const generation = ++flowGeneration;
    setFlow({ type: 'add', step: 'preparing' });
    void (async () => {
      try {
        // Refusal BEFORE any passkey ceremony (WM-68, WK-13).
        const preflight = await preflightManagement({ runtime, walletAddress: wallet });
        if (generation !== flowGeneration) return; // the flow was dismissed while checking
        if (preflight.state === 'refused') {
          log(`add(${mode}): sponsorship refused before consent`, preflight);
          setFlowIf(generation, refusedFlow(preflight));
          return;
        }
        const slot = await api.openPendingAddition();
        if (generation !== flowGeneration) {
          // Dismissed while opening: the slot must not stay claimable (WM-52).
          void api.declinePendingAddition(slot.id).catch(() => undefined);
          return;
        }
        activeSlot = { id: slot.id, settled: false };
        if (mode === 'this-device') {
          // WM-14: the same pending-addition machinery as the cross-device flow with the
          // handoff collapsed — this device opens the slot, creates the credential and
          // deposits it itself.
          const userId = await runtime.injection.encodeUserId(crypto.randomUUID().replace(/-/g, ''), runtime.factoryAddress, ChainType.EVM);
          const deposited = await deposit({ api, claimCode: slot.claimCode, userId, userName: config.branding.name });
          log('add(this-device): credential created and deposited', { fingerprint: deposited.fingerprint });
          toConfirmFingerprint(generation, slot.id, deposited.publicKey, deposited.fingerprint, mode);
        } else {
          log('add(second-device): pending addition opened', { slotId: slot.id, expiresAt: slot.expiresAt });
          setFlowIf(generation, {
            type: 'add',
            step: 'claim-code',
            claimCode: slot.claimCode,
            expiresAt: slot.expiresAt,
            cancel: () => void declineAdd(generation, slot.id, false),
          });
          startPolling(generation, slot.id);
        }
      } catch (err) {
        setFlowIf(generation, { type: 'add', step: 'error', message: (err as Error).message });
        log(`add(${mode}): failed`, (err as Error).message);
      }
    })();
  }

  // Poll the slot while the code is on screen (D8 phase 5): both devices are present and
  // awake at the same time by design.
  function startPolling(generation: number, slotId: string) {
    stopPolling();
    pollTimer = setInterval(() => {
      void (async () => {
        try {
          const slot = await api.getPendingAddition(slotId);
          if (generation !== flowGeneration) return stopPolling();
          if (slot.status === 'filled' && slot.publicKey) {
            stopPolling();
            // WM-20: recomputed from x,y AS RECEIVED — never trusted from the backend's own claim.
            const fingerprint = ownerFingerprint(publicKeyOwnerBytes(slot.publicKey.x, slot.publicKey.y));
            log('add(second-device): key deposited', { fingerprint });
            toConfirmFingerprint(generation, slotId, slot.publicKey, fingerprint, 'second-device');
          } else if (slot.status === 'expired') {
            stopPolling();
            activeSlot = null;
            setFlowIf(generation, { type: 'add', step: 'expired' }); // WM-23: distinct from a network failure
          }
        } catch (err) {
          if ((err as { code?: string }).code === 'pending-expired') {
            stopPolling();
            activeSlot = null;
            setFlowIf(generation, { type: 'add', step: 'expired' });
          }
        }
      })();
    }, pollIntervalMs);
  }

  function toConfirmFingerprint(generation: number, slotId: string, publicKey: { x: Hex; y: Hex }, fingerprint: string, mode: 'this-device' | 'second-device') {
    let name = '';
    const emit = () =>
      setFlowIf(generation, {
        type: 'add',
        step: 'confirm-fingerprint',
        fingerprint,
        name,
        setName: (value: string) => {
          name = value;
          emit();
        },
        approve: () => void approveAdd(generation, slotId, publicKey, () => name),
        // WM-21/WM-52: a mismatch is declined, counted, and nothing is added. On the
        // same-device flow a decline is simply a cancel back to the list.
        decline: () => void declineAdd(generation, slotId, mode === 'second-device'),
      });
    emit();
  }

  async function approveAdd(generation: number, slotId: string, publicKey: { x: Hex; y: Hex }, nameOf: () => string) {
    if (!me || generation !== flowGeneration) return;
    setFlow({ type: 'add', step: 'applying', chains: [] });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: me.walletAddress,
      label: 'add-owner',
      buildData: async () => encodeAddOwnerPublicKey(publicKey.x, publicKey.y),
      onProgress: (rows) => {
        if (flow?.type === 'add' && flow.step === 'applying') setFlowIf(generation, { ...flow, chains: rows });
      },
    });
    if (outcome.appliedChainIds.length > 0) {
      flowDirty = true;
      activeSlot = { id: slotId, settled: true };
      try {
        // The chain confirmed FIRST; only now does the registry bind (WM-15, WK-18) — and
        // only the chains that actually confirmed.
        const name = nameOf().trim();
        await api.completePendingAddition(slotId, { chainIds: outcome.appliedChainIds, name: name || undefined });
      } catch (err) {
        log('add: binding failed after on-chain success — the owner will show as added outside this deployment (WM-04)', (err as Error).message);
      }
    }
    setFlowIf(generation, { type: 'add', step: 'done', ok: outcome.ok, chains: outcome.progress, appliedChainIds: outcome.appliedChainIds, refusal: outcome.refusal });
  }

  async function declineAdd(generation: number, slotId: string, showDeclined: boolean) {
    stopPolling();
    await api.declinePendingAddition(slotId).catch(() => undefined);
    activeSlot = null;
    if (showDeclined) {
      log('add: fingerprint declined — nothing added');
      setFlowIf(generation, { type: 'add', step: 'declined' });
    } else {
      setFlowIf(generation, null);
    }
  }

  // ── the address flow (WM-24…WM-26) ──────────────────────────────────────────────

  function startAddAddress() {
    if (!me || flow) return;
    const wallet = me.walletAddress;
    const generation = ++flowGeneration;
    setFlow({ type: 'address', step: 'preparing' });
    void (async () => {
      const preflight = await preflightManagement({ runtime, walletAddress: wallet });
      if (generation !== flowGeneration) return;
      if (preflight.state === 'refused') {
        log('add-address: sponsorship refused before consent', preflight);
        setFlowIf(generation, refusedFlow(preflight));
        return;
      }
      toAddressInput(generation, '', null);
    })();
  }

  function toAddressInput(generation: number, value: string, inputError: AddressInputError | null) {
    let current = value;
    const emit = () =>
      setFlowIf(generation, {
        type: 'address',
        step: 'input',
        value: current,
        error: inputError,
        setAddress: (next: string) => {
          current = next;
          inputError = null;
          emit();
        },
        continue: () => {
          const candidate = current.trim();
          // WM-25: EIP-55 checksum correctness. viem's isAddress rejects a wrong mixed-case
          // checksum; an all-lowercase address carries no checksum to validate and is refused
          // so the user pastes the checksummed form their wallet displays.
          if (!isAddress(candidate)) {
            inputError = 'invalid-address';
            return emit();
          }
          if (candidate !== getAddress(candidate)) {
            inputError = 'not-checksummed';
            return emit();
          }
          if (me && candidate.toLowerCase() === me.walletAddress.toLowerCase()) {
            inputError = 'own-wallet';
            return emit();
          }
          toAddressConfirm(generation, candidate, current);
        },
      });
    emit();
  }

  function toAddressConfirm(generation: number, address: Address, rawInput: string) {
    let acknowledged = false;
    const emit = () =>
      setFlowIf(generation, {
        type: 'address',
        step: 'confirm',
        address,
        grantNotice: GRANT_NOTICE,
        acknowledged,
        acknowledge: (value: boolean) => {
          acknowledged = value;
          emit();
        },
        // The acknowledgement gates approval: an unacknowledged approve is a no-op, so a
        // view cannot skip the WM-26 statement by never rendering the checkbox.
        approve: () => {
          if (acknowledged) void approveAddress(generation, address);
        },
        back: () => toAddressInput(generation, rawInput, null),
      });
    emit();
  }

  async function approveAddress(generation: number, address: Address) {
    if (!me || generation !== flowGeneration) return;
    setFlow({ type: 'address', step: 'applying', chains: [] });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: me.walletAddress,
      label: 'add-address',
      buildData: async () => encodeAddOwnerAddress(address),
      onProgress: (rows) => {
        if (flow?.type === 'address' && flow.step === 'applying') setFlowIf(generation, { ...flow, chains: rows });
      },
    });
    if (outcome.appliedChainIds.length > 0) {
      flowDirty = true;
      // The registry has no row for an address owner; the audit trail still records the
      // change and who authorised it (WM-50).
      await api
        .recordOwnerEvent({ action: 'owner-added', ownerKind: 'address', owner: address, chainIds: outcome.appliedChainIds })
        .catch((err) => log('add-address: audit write failed', (err as Error).message));
    }
    setFlowIf(generation, {
      type: 'address',
      step: 'done',
      ok: outcome.ok,
      chains: outcome.progress,
      appliedChainIds: outcome.appliedChainIds,
      refusal: outcome.refusal,
    });
  }

  // ── removal (WM-27…WM-32) ───────────────────────────────────────────────────────

  function startRemove(owner: OwnerRow) {
    if (!me || flow) return;
    // WK-19/WM-28: the last remaining owner is refused legibly — there is no construction
    // that reaches `removeLastOwner`, and no flow is opened for it.
    if (state.owners.length <= 1) {
      error = 'the last remaining credential cannot be removed — that would lock the wallet forever; add another credential first';
      console.error('[giano-wallet-kit:manage] remove refused: last remaining owner (WM-28)');
      notify();
      return;
    }
    const generation = ++flowGeneration;
    setFlow({
      type: 'remove',
      step: 'confirm',
      owner,
      endsThisSession: owner.isCurrent,
      approve: () => void approveRemove(generation, owner),
      cancel: () => dismissFlow(),
    });
  }

  async function approveRemove(generation: number, owner: OwnerRow) {
    if (!me || generation !== flowGeneration) return;
    const wallet = me.walletAddress;
    setFlow({ type: 'remove', step: 'applying', chains: [] });
    const outcome = await applyOwnerChange({
      runtimes,
      walletAddress: wallet,
      label: 'remove-owner',
      buildData: async (chainRuntime) => {
        // WM-29: the index is read from THIS chain, now — never carried over from the
        // list render or from another chain, where indices can differ.
        const set = await readOwnerSet(chainRuntime.publicClient, wallet);
        const found = set.owners.find((candidate) => candidate.ownerBytes.toLowerCase() === owner.ownerBytes.toLowerCase());
        if (!found) return null; // not an owner on this chain — nothing to remove here
        if (set.owners.length === 1) {
          // Defence in depth for WM-28: the flow is never offered for the last owner, and
          // the contract would revert with LastOwner anyway — refuse legibly instead of
          // submitting a revert.
          throw new Error('this is the last owner on this chain — removal refused');
        }
        return encodeRemoveOwnerAtIndex(found.index, found.ownerBytes);
      },
      onProgress: (rows) => {
        if (flow?.type === 'remove' && flow.step === 'applying') setFlowIf(generation, { ...flow, chains: rows });
      },
    });

    let endedSession = false;
    if (outcome.appliedChainIds.length > 0) {
      flowDirty = true;
      if (owner.credentialId) {
        try {
          // The registry verifies on-chain before believing, then stops issuing sessions
          // for the credential (WM-31) — including this one, if it was removed (WM-30).
          const marked = await api.markCredentialRemoved(owner.credentialId);
          endedSession = marked.removedCurrentSession;
        } catch (err) {
          log('remove-owner: registry mark failed — the chain change stands; the registry will show the divergence', (err as Error).message);
        }
      } else {
        await api
          .recordOwnerEvent({
            action: 'owner-removed',
            ownerKind: owner.kind,
            owner: owner.kind === 'address' ? (owner.address as string) : owner.ownerBytes,
            chainIds: outcome.appliedChainIds,
          })
          .catch((err) => log('remove-owner: audit write failed', (err as Error).message));
      }
    }
    if (endedSession) {
      // The server already revoked the session (WM-30) — drop the local token too.
      await runtime.injection.logout().catch(() => undefined);
      pendingEndedSession = true;
    }
    setFlowIf(generation, {
      type: 'remove',
      step: 'done',
      ok: outcome.ok,
      endedSession,
      chains: outcome.progress,
      appliedChainIds: outcome.appliedChainIds,
      refusal: outcome.refusal,
    });
  }

  // ── the claim flow: the NEW device's half of a handoff (D8 phase 4, WM-19) ──────

  function startClaimOnThisDevice() {
    if (flow) return;
    toClaimInput(++flowGeneration, '');
  }

  function toClaimInput(generation: number, code: string) {
    let current = code;
    const emit = () =>
      setFlowIf(generation, {
        type: 'claim',
        step: 'input',
        code: current,
        setCode: (value: string) => {
          current = value;
          emit();
        },
        submit: () => void submitClaim(generation, current.trim()),
      });
    emit();
  }

  async function submitClaim(generation: number, code: string) {
    if (generation !== flowGeneration) return;
    setFlow({ type: 'claim', step: 'depositing' });
    try {
      const userId = await runtime.injection.encodeUserId(crypto.randomUUID().replace(/-/g, ''), runtime.factoryAddress, ChainType.EVM);
      const deposited = await deposit({ api, claimCode: code, userId, userName: config.branding.name });
      log('claim: passkey created and deposited', { fingerprint: deposited.fingerprint });
      // The fingerprint this device displays is computed from the key IT created (WM-20);
      // the user compares it on the authorising device's screen.
      setFlowIf(generation, { type: 'claim', step: 'deposited', fingerprint: deposited.fingerprint });
    } catch (err) {
      const apiCode = (err as { code?: string }).code ?? 'network';
      log('claim: failed', { code: apiCode, message: (err as Error).message });
      // WM-23: an expired, unknown or already-used code is refused with a machine-readable
      // reason the view keys its copy off — visibly different from a network failure.
      setFlowIf(generation, { type: 'claim', step: 'error', code: apiCode, message: (err as Error).message, retry: () => toClaimInput(generation, '') });
    }
  }

  // ── lifecycle ───────────────────────────────────────────────────────────────────

  function dismissFlow() {
    flowGeneration++; // invalidate any in-flight continuation of the dismissed flow
    stopPolling();
    if (activeSlot && !activeSlot.settled) {
      // An abandoned slot is declined so it cannot be consumed later (WM-52).
      void api.declinePendingAddition(activeSlot.id).catch(() => undefined);
    }
    activeSlot = null;
    flow = null;
    if (pendingEndedSession) {
      pendingEndedSession = false;
      flowDirty = false;
      resetToSignedOut();
      notify();
      return;
    }
    const reload = flowDirty;
    flowDirty = false;
    notify();
    if (reload) void load();
  }

  return {
    get state() {
      return state;
    },
    get flow() {
      return flow;
    },
    subscribe(listener) {
      listeners.add(listener);
      listener(state);
      return () => listeners.delete(listener);
    },
    load,

    signIn: () =>
      withBusy(async () => {
        await runtime.provider.request({ method: 'eth_requestAccounts' });
        await load();
      }),

    signInWithExistingPasskey: () =>
      withBusy(async () => {
        // Discoverable sign-in: how a device uses a passkey it gained through a handoff —
        // possible because every credential the kit creates is discoverable (WK-20).
        const result = await runtime.injection.signInWithExistingPasskey();
        log('signed in with existing passkey', { walletAddress: result.walletAddress });
        await load();
      }),

    logout: () =>
      withBusy(async () => {
        await runtime.injection.logout();
        resetToSignedOut();
      }),

    rename: (credentialId, name) =>
      withBusy(async () => {
        await api.renameCredential(credentialId, name);
        log('credential renamed', { credentialId, name });
        await load();
      }),

    startAddThisDevice: () => startAdd('this-device'),
    startAddSecondDevice: () => startAdd('second-device'),
    startAddAddress,
    startRemove,
    startClaimOnThisDevice,
    dismissFlow,

    destroy() {
      stopPolling();
      listeners.clear();
    },
  };
}
