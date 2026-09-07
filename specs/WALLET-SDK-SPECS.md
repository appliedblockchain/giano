# Giano wallet SDK — API specification

The client-facing API of the wallet SDK ("the kit") specified by
[`WALLET-SDK-REQUIREMENTS.md`](./WALLET-SDK-REQUIREMENTS.md): the functions, types and state a
client writes against to build a Giano **wallet origin** — Giano's stock wallet and a
bring-your-own-UI tenant alike.

This document describes **what a client calls and what it gets back**, with usage examples. It
contains no implementation — every code block is a client using the kit, or a type the kit exports.
The type declarations are the API contract; the surrounding examples show how a wallet UI is
assembled from them. The kit is **headless**: it owns the orchestration and emits state and actions;
the client owns every pixel.

Status: **draft, in review.** Names and shapes are the proposed surface, not yet published.

> **Relationship to the requirements.** Each section notes the `WK-nn` it realises. The invariants
> the kit holds by construction ([requirements §5](./WALLET-SDK-REQUIREMENTS.md)) are not the
> client's to uphold — they are the reason the surface looks the way it does.

---

## Contents

1. [Packages and entry points](#1-packages-and-entry-points)
2. [Configuration](#2-configuration)
3. [Runtimes](#3-runtimes)
4. [The host and consent](#4-the-host-and-consent)
5. [The wallet-management controller](#5-the-wallet-management-controller)
6. [Sponsorship pre-flight](#6-sponsorship-pre-flight)
7. [The React adapter](#7-the-react-adapter)
8. [End to end: a wallet origin, whole](#8-end-to-end-a-wallet-origin-whole)
9. [Errors](#9-errors)

---

## 1. Packages and entry points

The kit ships one package with two entry points (WK-22, WK-23):

| Import | What it is | Depends on a framework? |
|---|---|---|
| `@appliedblockchain/giano-wallet-kit` | The framework-free core: config, runtimes, host, management controller. | No |
| `@appliedblockchain/giano-wallet-kit/react` | Thin React hooks over the core. Adds no capability the core lacks. | React |

A vanilla-DOM wallet imports only the core. A React wallet imports the core for wiring and the
`/react` entry for rendering. The dApp side is a different package entirely
(`@appliedblockchain/giano-connector`) and is not covered here.

---

## 2. Configuration

Realises WK-06, WK-07. The client supplies configuration; the kit validates it and fails fatally,
naming the chain and field, on anything incomplete.

```ts
import type { WalletConfig, WalletChainConfig } from '@appliedblockchain/giano-wallet-kit'

interface WalletConfig {
  /** Base URL of the wallet-api; '/api' when proxied same-origin. */
  walletApiUrl: string
  /** dApp origins allowed to open this wallet. Empty = none (fail closed). */
  allowedDappOrigins: string[]
  /** The WebAuthn relying-party id — the wallet origin's hostname. */
  rpId: string
  branding: { name: string; logoUrl?: string }
  /** The closed list of chains this wallet serves. Never empty. */
  chains: WalletChainConfig[]
}

interface WalletChainConfig {
  chainId: number
  name: string          // human-readable; named on every consent screen
  rpcUrl: string
  bundlerUrl: string
  factoryAddress: `0x${string}`
  sponsorship: 'service' | 'test-paymaster' | 'off'
  paymasterServiceUrl?: string      // defaults to `${walletApiUrl}/v1/paymaster`
  testPaymasterAddress?: `0x${string}`
}
```

**Usage — construct it directly:**

```ts
const config: WalletConfig = {
  walletApiUrl: '/api',
  allowedDappOrigins: ['https://app.example.com'],
  rpId: 'wallet.example.com',
  branding: { name: 'Example Wallet' },
  chains: [
    { chainId: 8453, name: 'Base', rpcUrl: 'https://…', bundlerUrl: 'https://…',
      factoryAddress: '0x26dC…', sponsorship: 'service' },
  ],
}
```

**Usage — load the stock `/config.json` shape** (convenience helper; the multi-chain list and the
single-chain shorthand are both accepted, and supplying both is a fatal error):

```ts
import { loadWalletConfig } from '@appliedblockchain/giano-wallet-kit'

const config = await loadWalletConfig()          // fetches and validates /config.json
```

---

## 3. Runtimes

Realises WK-01…WK-05. `createWalletRuntimes` turns validated config into **per-chain runtimes**,
built lazily and memoised, over **one shared** wallet-api session. Everything chain-bound — bundler,
fee estimation, paymaster hooks, provider, sponsorship pre-flight — lives on the runtime; the client
never wires a bundler or resolves a fee itself, and so cannot get the fee-before-paymaster ordering
wrong.

```ts
import { createWalletRuntimes } from '@appliedblockchain/giano-wallet-kit'
import type { WalletRuntimes, WalletRuntime, SponsorshipPreflight } from '@appliedblockchain/giano-wallet-kit'

interface WalletRuntimes {
  readonly servedChainIds: readonly number[]
  /** Built on first use, then memoised. */
  runtimeFor(chainId: number): WalletRuntime
  descriptorFor(chainId: number): WalletChainConfig
}

interface WalletRuntime {
  readonly chainId: number
  readonly chainName: string
  /** The EIP-1193 provider for this chain (from giano-wallet-core). */
  readonly provider: GianoProvider
  /** The shared wallet-api session, held once across all runtimes. */
  readonly injection: WalletApiInjection
  isAccountDeployed(address: `0x${string}`): Promise<boolean>
  /** Answered before any approve button or passkey prompt is offered. */
  checkSponsorship(tx: { to?: `0x${string}`; value?: bigint; data?: `0x${string}` }): Promise<SponsorshipPreflight>
}
```

**Usage:**

```ts
const runtimes = createWalletRuntimes(config)

runtimes.servedChainIds                         // e.g. [8453, 84532]
const runtime = runtimes.runtimeFor(8453)       // built here, reused next time

const token = runtime.injection.getSessionToken()   // null when signed out
const deployed = await runtime.isAccountDeployed('0x1234…')
```

---

## 4. The host and consent

Realises WK-08…WK-12. `createWalletHost` wires the popup transport — origin pinning, chain
negotiation, the consent gate, and the `giano_openWalletManagement` method — and exposes the pending
request as **subscribable state**. The host awaits the user's decision; the client renders the
request and calls `approve()` / `reject()`. A rejection becomes EIP-1193 `4001`; the client writes no
transport code.

```ts
import { createWalletHost } from '@appliedblockchain/giano-wallet-kit'
import type { WalletHost, PendingRequest } from '@appliedblockchain/giano-wallet-kit'

interface WalletHost {
  /** Attach transport listeners and announce readiness to the opener. */
  start(): void
  stop(): void
  /** The single-slot pending-request queue. */
  readonly requests: {
    readonly current: PendingRequest | null
    subscribe(listener: (pending: PendingRequest | null) => void): () => void
  }
  /** The pinned dApp origin, or null before the handshake. */
  readonly dappOrigin: string | null
}

interface PendingRequest {
  /** 'manage' opens the management view; the others gate a ceremony. */
  kind: 'connect' | 'transaction' | 'sign' | 'manage'
  method: string
  params: unknown
  dappOrigin: string
  chainId: number
  chainName: string           // every consent screen names the chain
  runtime: WalletRuntime
  approve(): void
  reject(): void
}
```

**Usage — a vanilla wallet origin's whole request loop:**

```ts
const host = createWalletHost({ runtimes, config, walletVersion: '1.0.0' })
host.start()

host.requests.subscribe((pending) => {
  if (!pending) return renderIdle()
  switch (pending.kind) {
    case 'connect':     return renderConnect(pending)      // "Connect your wallet" → pending.approve()
    case 'transaction': return renderReview(pending)       // show tx + sponsorship pre-flight
    case 'sign':        return renderSign(pending)         // show the payload
    case 'manage':      return renderManagement(pending)   // mount the management controller (§5)
  }
})
```

The client decides what a consent screen looks like; the kit decides *when* one is required and what
it is about. A `manage` request resolves — `pending.approve()` — when the user closes the management
view, which is what returns nothing to the calling application (WM-40).

---

## 5. The wallet-management controller

Realises WK-16…WK-21. `createManagementController` drives the whole of wallet management as a
headless state machine. It reads the owner set from the chain, reconciles it against the registry,
and runs the add/remove/handoff flows — holding every ordering invariant (chain-before-registry,
per-chain index re-read, fingerprint recompute) inside itself. The client renders `state` and calls
actions; it never constructs an owner-set operation.

```ts
import { createManagementController } from '@appliedblockchain/giano-wallet-kit'
import type { ManagementController, ManagementState, OwnerRow, ManagementFlow } from '@appliedblockchain/giano-wallet-kit'

interface ManagementController {
  readonly state: ManagementState
  subscribe(listener: (state: ManagementState) => void): () => void
  load(): Promise<void>

  // ── sign-in (WK offers both, WM-57) ──
  signIn(): Promise<void>                       // create-or-use a passkey on this device
  signInWithExistingPasskey(): Promise<void>    // discoverable: a device handed a credential via handoff
  logout(): Promise<void>

  // ── the set ──
  rename(credentialId: string, name: string | null): Promise<void>

  // ── start a flow (each drives its own sub-state, below) ──
  startAddThisDevice(): void                    // WM-14
  startAddSecondDevice(): void                  // WM-18…WM-23
  startAddAddress(): void                       // WM-24…WM-26
  startRemove(owner: OwnerRow): void            // WM-27…WM-32
  startClaimOnThisDevice(): void                // the NEW device's side of a handoff

  // ── act within the active flow ──
  readonly flow: ManagementFlow | null
}

interface ManagementState {
  view: 'signed-out' | 'loading' | 'set' | 'unreadable' | 'flow'
  walletAddress: `0x${string}` | null
  /** The owner set read from the reference chain, joined to the registry by owner bytes. */
  owners: OwnerRow[]
  /** Registry rows the chain does not back — shown as NOT owners, never omitted (WM-04). */
  strays: OwnerRow[]
  /** True when served chains disagree on the owner set — a problem, not a list (WM-06). */
  divergent: boolean
  /** Per-chain deployment/readability, so the client can say "unreachable" vs "one credential". */
  chains: { chainId: number; chainName: string; deployed: boolean | null }[]
  error: string | null
}

interface OwnerRow {
  kind: 'passkey' | 'address'
  /** Stable, human-comparable id derived from the owner bytes (WM-03). */
  fingerprint: string
  /** Set for kind 'address'. */
  address?: `0x${string}`
  /** The user-set name, when the registry has a row for this owner. */
  name: string | null
  /** True for the credential the current session uses (WM-10). */
  isCurrent: boolean
  createdAt: string | null
  transports: string[] | null
  /** Present when the registry shows it removed but the chain still lists it, or vice-versa. */
  removedAt: string | null
}
```

The **flow** is where a client renders each step. Every step carries exactly the data the screen
needs — the client compares nothing itself:

```ts
type ManagementFlow =
  // add on this device / from a second device
  | { type: 'add'; step: 'preparing' }
  | { type: 'add'; step: 'claim-code'; claimCode: string; expiresAt: string }        // show on device A
  | { type: 'add'; step: 'confirm-fingerprint'; fingerprint: string;                 // compare on both screens
      setName(name: string): void; approve(): void; decline(): void }
  | { type: 'add'; step: 'applying'; chains: ChainProgress[] }                        // per-chain progress
  | { type: 'add'; step: 'done'; ok: boolean; chains: ChainProgress[] }
  | { type: 'add'; step: 'declined' } | { type: 'add'; step: 'expired' }

  // add an externally-owned account
  | { type: 'address'; step: 'input'; setAddress(v: string): void; error: string | null; continue(): void }
  | { type: 'address'; step: 'confirm'; address: `0x${string}`;                       // full, unabbreviated (WM-25)
      grantNotice: string; acknowledge(): void; approve(): void }                     // "full and equal control" (WM-26)
  | { type: 'address'; step: 'applying'; chains: ChainProgress[] }
  | { type: 'address'; step: 'done'; ok: boolean; chains: ChainProgress[] }

  // remove
  | { type: 'remove'; step: 'confirm'; owner: OwnerRow; endsThisSession: boolean; approve(): void; cancel(): void }
  | { type: 'remove'; step: 'applying'; chains: ChainProgress[] }
  | { type: 'remove'; step: 'done'; ok: boolean; endedSession: boolean; chains: ChainProgress[] }

  // the new device claiming a code
  | { type: 'claim'; step: 'input'; setCode(v: string): void; submit(): void }
  | { type: 'claim'; step: 'deposited'; fingerprint: string }                         // now compare on device A
  | { type: 'claim'; step: 'error'; code: string; message: string }                   // actionable, distinct from a network error

  // a sponsorship refusal met before any passkey prompt (WM-48, WM-49)
  | { type: 'refused'; reason: SponsorshipRefusalReason; message: string; back(): void }

interface ChainProgress {
  chainId: number
  chainName: string
  state: 'waiting' | 'checking' | 'skipped' | 'refused' | 'submitted' | 'confirmed' | 'failed'
  detail?: string
  userOpHash?: string
}
```

**Usage — mount it when a `manage` request arrives, render its state:**

```ts
function renderManagement(pending: PendingRequest) {
  const mgmt = createManagementController({ runtimes, config })
  const unsubscribe = mgmt.subscribe(render)
  void mgmt.load()

  function render(state: ManagementState) {
    if (state.view === 'signed-out') return renderSignIn(mgmt)     // buttons → mgmt.signIn() / signInWithExistingPasskey()
    if (state.view === 'unreadable') return renderUnreadable(mgmt) // WM-05: say the chain could not be read
    if (mgmt.flow)                   return renderFlow(mgmt.flow)   // the step machine above
    return renderOwnerList(state, mgmt)                            // the set, with rename / add / remove buttons
  }

  // when the user closes the view, resolve the transport request (returns nothing to the dApp)
  onClose(() => { unsubscribe(); pending.approve() })
}
```

**Usage — the owner list and its actions:**

```ts
function renderOwnerList(state: ManagementState, mgmt: ManagementController) {
  for (const owner of state.owners) {
    line(owner.name ?? (owner.kind === 'address' ? 'Ethereum account' : 'Passkey'),
         owner.fingerprint, owner.isCurrent ? 'this session' : '')
    if (owner.name !== undefined) button('Rename', () => mgmt.rename(credentialIdOf(owner), promptName()))
    // the last remaining owner offers no remove button (WM-28)
    button('Remove', () => mgmt.startRemove(owner), { disabled: state.owners.length <= 1 })
  }
  button('Add a passkey on this device', () => mgmt.startAddThisDevice())
  button('Add a passkey on another device', () => mgmt.startAddSecondDevice())
  button('Add an Ethereum account', () => mgmt.startAddAddress())
}
```

**Usage — the cross-device handoff, entirely from `flow`:**

```ts
function renderFlow(flow: ManagementFlow) {
  if (flow.type === 'add' && flow.step === 'claim-code')
    return show(`Enter this on your other device: ${flow.claimCode}`)   // device A

  if (flow.type === 'add' && flow.step === 'confirm-fingerprint') {     // device A, after B deposited a key
    show(`Approve only if your other device shows: ${flow.fingerprint}`)
    button('They match — add it', flow.approve)                          // raises the passkey prompt
    button('They don’t match',    flow.decline)                          // counted; nothing added (WM-52)
  }

  if (flow.step === 'applying')
    return flow.chains.forEach((c) => line(`${c.chainName}: ${c.state}`)) // per-chain progress (WM-44)
}
```

Because the fingerprint the client displays comes from `flow.fingerprint` (recomputed by the
controller from the key as received), and the per-chain application is the controller's, the client
gets WM-15/WM-20/WM-29/WM-44 for free — it renders strings and wires buttons.

---

## 6. Sponsorship pre-flight

Realises WK-13…WK-15. The runtime answers whether an operation would be sponsored **before** consent.
The kit returns the machine-readable reason; the client owns the copy (the kit ships none).

```ts
type SponsorshipPreflight =
  | { state: 'not-applicable' }                    // sponsorship off — the user pays, nothing to explain
  | { state: 'sponsored' }
  | { state: 'refused'; reason: SponsorshipRefusalReason; message: string; ruleResults: SponsorshipRuleResult[] }
  | { state: 'unavailable'; message: string }      // an outage — retryable, unlike a refusal

type SponsorshipRefusalReason =
  | 'sponsorship-disabled' | 'no-sponsorship-config' | 'contract-not-allowed'
  | 'function-not-allowed' | 'wallet-management-not-sponsored' | 'cost-exceeds-cap'
  | 'insufficient-balance' | 'tenant-in-deficit' | 'not-your-wallet'
```

**Usage — gate the approve button on the answer (no approve, no passkey prompt, when refused):**

```ts
const preflight = await pending.runtime.checkSponsorship(txOf(pending.params))

if (preflight.state === 'refused') {
  showRefusal(myCopyFor(preflight.reason))   // the client's own wording, keyed off the reason
  showOnly('Close')                          // deliberately no approve button (WM-68)
} else {
  showApprove(() => pending.approve())
}
```

---

## 7. The React adapter

Realises WK-23. `@appliedblockchain/giano-wallet-kit/react` exposes the same core as hooks — nothing
the core cannot do, only idiomatic for React.

```tsx
import { WalletHostProvider, usePendingRequest, useManagement } from '@appliedblockchain/giano-wallet-kit/react'

function App({ config }: { config: WalletConfig }) {
  return (
    <WalletHostProvider config={config} walletVersion="1.0.0">
      <Popup />
    </WalletHostProvider>
  )
}

function Popup() {
  const pending = usePendingRequest()               // re-renders on each request
  if (!pending) return <Idle />
  if (pending.kind === 'connect')     return <Connect request={pending} />
  if (pending.kind === 'transaction') return <Review request={pending} />
  if (pending.kind === 'sign')        return <Sign request={pending} />
  if (pending.kind === 'manage')      return <Manage onClose={pending.approve} />
}

function Manage({ onClose }: { onClose: () => void }) {
  const { state, flow, actions } = useManagement()   // load() runs on mount
  // render `state.owners`, call `actions.rename(...)`, `actions.startAddSecondDevice()`, drive `flow`
}
```

`useManagement()` returns `{ state, flow, actions }` — the controller's state and actions, re-rendered
on change. The component tree is the client's; the hook is the whole of the wiring.

---

## 8. End to end: a wallet origin, whole

A complete, framework-free wallet origin — everything a client writes — is the config, the runtimes,
the host, and a render function per request kind:

```ts
import { loadWalletConfig, createWalletRuntimes, createWalletHost } from '@appliedblockchain/giano-wallet-kit'

const config   = await loadWalletConfig()
const runtimes = createWalletRuntimes(config)
const host     = createWalletHost({ runtimes, config, walletVersion: '1.0.0' })

host.requests.subscribe((pending) => {
  if (!pending)                       return renderIdle(config.branding)
  if (pending.kind === 'connect')     return renderConnect(pending)
  if (pending.kind === 'transaction') return renderReviewWithPreflight(pending)   // §6
  if (pending.kind === 'sign')        return renderSign(pending)
  if (pending.kind === 'manage')      return renderManagement(pending)            // §5
})

host.start()

// The same three lines, plus a render function, are all wallet-web and wallet-byo share.
// What differs between them is only the render functions — the pixels.
```

Opening the wallet origin directly (not via a dApp popup) mounts the management controller straight
away rather than waiting for a request — the two entry points present the same capabilities (WM-56):

```ts
if (!window.opener) renderManagementStandalone(runtimes, config)  // createManagementController(...).load()
```

---

## 9. Errors

The kit surfaces two error shapes a client handles, both carrying machine-readable codes so a client
keys behaviour off the code, never the prose:

```ts
// From the wallet-management API (pending additions, binding, removal).
class WalletManagementApiError extends Error {
  readonly code: string      // e.g. 'pending-expired', 'still-an-owner', 'not-an-owner-on-chain'
  readonly status: number
}

// From the transport, when a request cannot proceed.
class TransportRpcError extends Error {
  readonly code: number      // EIP-1193: 4001 rejected, 4100 unauthorized, 4900 disconnected, …
}
```

**Usage — distinguish an expired handoff from a network failure (WM-23):**

```ts
// The controller already surfaces this as flow `{ type: 'claim', step: 'error', code, message }`,
// so a client rendering `flow` needs no try/catch. When calling the management API directly:
try {
  await api.completePendingAddition(id, { chainIds })
} catch (e) {
  if (e instanceof WalletManagementApiError && e.code === 'pending-expired') showExpired()
  else showNetworkProblem()
}
```

Refusals, expiries and outcomes are also written to the browser console by the controller (WM D10),
so an integrator debugging a deployment is not dependent on a transient banner.

---

## Related documents

- [`specs/WALLET-SDK-REQUIREMENTS.md`](./WALLET-SDK-REQUIREMENTS.md) — why the kit exists and what it
  must do; every `WK-nn` cited here is defined there
- [`specs/WALLET-MANAGEMENT-REQUIREMENTS.md`](./WALLET-MANAGEMENT-REQUIREMENTS.md) — the `WM-nn` the
  management controller (§5) realises
- [`specs/INTEGRATION.md`](./INTEGRATION.md) — where this surface is documented for tenants (WK-33)
- [`specs/MULTICHAIN_SPECS.md`](./MULTICHAIN_SPECS.md) §6 — the dApp SDK (`giano-connector`), the
  wallet side's counterpart
