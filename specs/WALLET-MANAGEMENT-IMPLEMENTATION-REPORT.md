# Wallet management — implementation report

Companion to [`WALLET-MANAGEMENT-REQUIREMENTS.md`](./WALLET-MANAGEMENT-REQUIREMENTS.md), written
alongside the implementation on `experimental_wallet_management`. It records where the build
**diverges from, defers, or reinterprets** a requirement, and the reasoning, for review after the
UI lands. Requirements not listed here were implemented as written.

Status: **for review.**

---

## 1. The one substantive divergence: owner changes use the chain-bound path, not the replayable one

**Requirements affected:** WM-41 (apply an owner change to every served chain from a single
authorisation, via `executeWithoutChainIdValidation`), WM-45 (treat the retained chain-independent
authorisation as a credential-equivalent secret), and D6.

**What was built instead:** the interface applies each owner change as a **chain-bound
`execute(address(this), …)` self-call, once per served chain** — which is what WM-42 mandates for a
single-chain deployment — even when several chains are served. Each chain takes its own passkey
signature, sequentially, with the per-chain progress WM-44 requires.

**Why.** The replayable path (WM-41) is unreachable through the *rest of the deployed system* as it
stands today, for two independent reasons:

1. **Sponsorship is chain-bound by construction.** A sponsored operation carries an EIP-712
   paymaster authorisation whose domain pins `chainId` and the paymaster's `verifyingContract`
   (`services/wallet-api/src/services/sponsorship-signer.ts`, `authorisationDomain`). The signature
   the paymaster verifies on chain is therefore valid on exactly one chain. A single
   `executeWithoutChainIdValidation` user-operation replayed across chains would need a paymaster
   authorisation valid across chains, which the paymaster contract does not accept. WM-47 requires
   these operations to be sponsored under the existing platform rule; a replayable authorisation
   and a chain-bound sponsorship cannot both be honoured by today's paymaster.

2. **The relay only admits decodable `execute`/`executeBatch` calls.** The sponsorship rules engine
   (`sponsorship-rules.ts`, `decodeInnerCalls`) refuses any operation it cannot decode as
   `execute`/`executeBatch`, and detects wallet management structurally as a self-call inside one.
   `executeWithoutChainIdValidation` takes `bytes[]` of raw self-calls and is a *different*
   selector; the relay would refuse it as "not a decodable execute/executeBatch call", so it could
   not be sponsored, and an unsponsored owner change defeats the whole reason wallet management is
   platform-sponsored (a user on a new device holds no native token — §1.4 of the requirements).

The multichain memory and `specs/MULTICHAIN_SPECS.md` §10.5 already record that the **paymaster
domain change for chain-independent wallet-management sponsorship was deliberately deferred** (the
"S12/phase 8" item), and the owner-set **convergence job** (§11, phase 9) with it. WM-41/WM-45 sit
downstream of exactly that deferred work: until the paymaster can sponsor a chain-independent
operation, the replayable path cannot be both used *and* sponsored, and D6's own text says a
single-chain deployment "gains nothing from the replayable path and inherits its whole risk" — the
chain-bound path is strictly safer, just more passkey prompts on a multi-chain deployment.

**Consequences the reviewer should weigh:**

- **WM-44's "retryable without a further passkey prompt".** With the chain-bound path there is no
  single retained authorisation to reuse, so an outstanding chain is retried with a *fresh* signature
  — one passkey prompt per chain, per attempt. On the two-chain devnet this means the user confirms
  the passkey once per chain. This is a UX regression against WM-41's "one passkey prompt", not a
  security one.
- **WM-45 is satisfied vacuously.** No chain-independent authorisation is ever created or retained,
  so there is no credential-equivalent secret to protect or delete. The attacker row in §5.2 for "a
  leaked chain-independent authorisation" does not arise in this build.
- **Convergence is still eventual and still visible.** Because each chain is applied separately, a
  wallet genuinely can have two owners on one chain and one on another for a while — WM-44 makes it
  visible per chain and the owner-set-divergence banner (WM-06/WM-53) surfaces it; the interface
  never reports a change complete until every non-skipped chain confirms (D10).

**To close WM-41/WM-45 as written** the paymaster needs the chain-independent sponsorship domain
(MULTICHAIN_SPECS §10.5) and the relay needs to admit and structurally classify
`executeWithoutChainIdValidation`. Both are contract/relay changes outside this UI work, and the
requirements themselves cite that path as owed by the multichain spec rather than built here. The
`applyOwnerChange` engine (`services/wallet-web/src/views/manage/ops.ts`) is the single place that
would switch paths, and its per-chain loop is written so that swapping to a
"sign once, replay per chain" strategy is a localised change.

---

## 2. Deferred with the requirement's blessing

- **WM-53 operational alert (owner set differs between chains).** The requirements scope v1 to "the
  alert, not an operator console" (§2.3), and MC-37's operator-side reconciliation tooling is
  explicitly out of scope. Implemented: the interface surfaces divergence to the user (WM-06 banner)
  and writes a `console.error` an integrator can see. **Not implemented:** a server-side metric/alert
  firing when the watcher observes divergent sets, because the owner-set convergence watcher (§11 of
  the multichain spec) was itself deferred. When that watcher lands, it is the right place to emit
  the alert. Flagged so the alerting half of WM-53 is not assumed present.

- **WM-46 / Q2 (managing a wallet before it is deployed on a chain).** Implemented per the
  requirement's own recommendation ("apply the change only to deployed chains and reconcile the rest
  on first use as MC-38 already does"): a chain where the account has no code is **skipped with a
  stated reason** rather than deployed. The requirement leaves this needing confirmation against
  MC-38's mechanism; that confirmation is still owed.

---

## 3. Reinterpretations worth confirming

- **WM-25 EIP-55 validation.** The interface requires the address to be entered in its **checksummed
  (mixed-case) form** and rejects an all-lowercase address, because an all-lowercase string carries
  no checksum to validate, and accepting it would defeat the point of the check. A user pasting the
  address their own wallet displays (always checksummed) is unaffected; a user hand-typing a
  lowercase address is asked to use the checksummed form. Confirm this is the intended strictness.

- **WM-31 "the registry stops issuing sessions for that credential".** Implemented by marking the
  credential `removed_at` **only after the change is confirmed on-chain** (the endpoint reads
  `isOwnerPublicKey` from the account contract and refuses to mark a still-present owner). This is
  stricter than the literal text and follows D1/WM-36 (chain governs): the registry never refuses a
  credential the chain still accepts. The consequence is that removal's registry step depends on a
  readable chain; if no served chain can be read at that moment the mark is deferred (the on-chain
  removal still stands, and the divergence shows via WM-04) rather than marking optimistically.

- **WM-33 discoverable sign-in.** A device whose credential was added through a cross-device handoff
  has never seen the wallet locally, so it signs in with a **discoverable** passkey (no
  `allowCredentials`) and the injection **adopts the canonical external user id** the server returns.
  This required `authentication/verify` to return `externalUserId` (it already did) and the injection
  to persist it. No requirement forbids this; noting it because it is the mechanism that makes WM-33
  actually usable from a fresh device, and it slightly widens what a sign-in can change client-side.

- **WM-08 initial name (Q5).** The discarded `credentialName` is now **persisted as the initial
  name**. The stock wallet still sends the tenant brand name for a *first* credential (unchanged),
  which distinguishes nothing (D7) — but it no longer sends it for management-added credentials,
  which pass a user-entered name. Q5 (who may set the initial name) remains a product decision; this
  build persists whatever is sent rather than dropping it, satisfying WM-08's "either persist or
  remove" without foreclosing the generated-default option.

---

## 4. Faithful to the requirement, but worth a reviewer's eye

- **WM-28 `removeLastOwner` unreachable.** There is no encoder for `removeLastOwner` anywhere in the
  SDK, the stock UI, or the BYO reference; the remove button is disabled and a note explains why when
  one owner remains; and the per-chain remove builder refuses if it finds itself the last owner on a
  chain. Three layers, none of which construct the selector.

- **WM-52 declined fingerprints counted.** A decline writes a `pending-declined` row to
  `wallet_management_log` and increments the `giano_wallet_management_events_total{action="pending-declined"}`
  counter, documented as alertable. The alert *rule* itself is a deployment concern (as with the
  existing sponsorship alerts), not shipped here.

- **WM-16 binding refused for a foreign session.** A pending addition is resolvable only by the
  session that opened it (matched on tenant, user *and* wallet), and completion re-checks all three;
  a foreign session gets an indistinguishable 404 (no oracle). Covered by
  `wallet-management.test.ts`.

- **Audit for address-owner changes (WM-50).** An externally-owned account has no registry row, so
  its add/remove is recorded through `POST /v1/wallet/owner-events` from the interface. This is an
  audit **write from the client**, which the client could omit — but the requirement's audit
  guarantee for address owners is inherently limited anyway (§5.3: an address owner can act *without*
  the EntryPoint, outside the relay's audit trail entirely), and WM-26 already requires telling the
  user exactly that. The relayed *addition/removal* transaction is audited by `userop_log`
  regardless; only the management-layer annotation is client-driven.

---

## 5. Test coverage map

- **wallet-api integration** (`services/wallet-api/test/wallet-management.test.ts`, 13 cases):
  naming/persistence, the full pending-addition lifecycle including the chain-confirms-before-bind
  ordering, WM-16 foreign-session refusal, WM-22/WM-23 expiry and decline with distinct reasons,
  the per-user open-slot cap, removal with the chain-governs guard, self-removal ending the session,
  and WM-31 authentication refusal. The mock chain (`test/setup.ts`) plays the account contract's
  owner-set reads so the "chain governs" ordering is actually exercised, not stubbed.
- **wallet-core unit** (`packages/wallet-core/test/management.test.ts`): owner-bytes encoding,
  fingerprint stability/uniqueness, the management calldata encoders, and owner-set divergence.
- **e2e** (`e2e/tests/wallet-management.spec.ts`): view with the on-chain set asserted and the
  current session marked; same-session passkey add with two owners on-chain and the address
  unchanged; add an externally-owned account with the full-address consent; remove with the on-chain
  set shrinking and the last-owner guard; rename persistence; the app-opened path returning no data
  (WM-39/WM-40); and BYO parity. Each mutation asserts the **on-chain owner set** (WM-67), not merely
  a succeeding transaction.

**Cross-device handoff (WM-18) is covered at the API layer, not yet in the browser e2e.** The
two-device fingerprint-compare flow needs two independent CDP virtual authenticators in two
browser contexts driving one wallet origin; the backend lifecycle it depends on is fully covered by
the integration suite (open → claim → fill → poll → complete, plus decline and expiry). A browser
e2e for the two-device UI is the main testing gap and is called out here rather than left implicit.
