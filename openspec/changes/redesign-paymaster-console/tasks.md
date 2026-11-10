## 1. Bugs (`fix/paymaster-console-bugs`)

- [x] 1.1 Refuse a `refreshSeconds` that isn't a non-negative number at config load, instead of polling with `setInterval(NaN)`.
- [x] 1.2 Timelock tab: after a failed first read, show "Nothing to show" with Try again instead of a spinner that never stops.
- [x] 1.3 Registry table: `colSpan` 6 on the empty row, matching the six columns.
- [x] 1.4 Admins table: rename the "PlatformAdmin" column header to "Admin"; remove the stray `console.log` calls.
- [x] 1.5 Rename `HistoryEntry.platformSessionId` to `platformAdminSessionId`, as wallet-api returns it.
- [x] 1.6 Show the error when the Fund amount doesn't parse, when the deleted-tenants read fails, and when the drawer's history read fails.

## 2. Theme

- [x] 2.1 Replace `theme.ts`:
  - the system font stack, plus the `brand` and `accent` palettes with light and dark semantic tokens, as in custom-example;
  - a white `canvas`;
  - the `timelock` semantic palette (D5).
- [x] 2.2 Add colour mode: the `.dark` class on `<html>`, a hook, and a pre-paint script in `public/` (D4). Add a toggle in the header.
- [x] 2.3 Check every existing panel in light and dark mode on the e2e stack, and fix any hard-coded colour.

## 3. Shell and navigation

- [x] 3.1 Add `lib/router.tsx`: `useRoute`, `navigate`, `<Link>`, the route table, and an unknown-route view (D1).
- [x] 3.2 Split `App.tsx` into `shell/Header.tsx` and `shell/TabBar.tsx`, a route outlet, and the existing connect and deployment logic.
  - The header: logo, title, deployment select, paymaster address, session pill, wallet with disconnect, colour-mode toggle.
  - The status line: health level, invariant, paused, last refresh. The queued count and the block moved to 4.7 (G1).
- [x] 3.3 One tab bar: Overview, Tenants, Paymaster, Roles, Timelock, Activity, Health, Admins. Admins only with `platformApi`. Remove the area switch (D2). Mount the existing panels under their new routes unchanged.
- [x] 3.4 The sign-in page with its steps, shown in place of any path until there is a session. After sign-in, that path renders.
- [x] 3.5 The session warning two minutes before expiry, with Stay signed in (a fresh signature) and Sign out (K8).
- [x] 3.6 Wallet disconnect (C10). It also signs out, because the session was signed by that wallet.
- [x] 3.7 Pause polling while the tab is hidden, and refresh the registry with everything else (C7).
- [x] 3.8 e2e: move the console specs to the new tab names and routes; add a deep-link case and an unknown-route case.

## 4. Shared primitives

- [x] 4.1 `useChainAction` and `<ActionButton>`: send, propose or blocked, with the missing role named (D6, C2, C3).
- [x] 4.2 `ConfirmDialog` for destructive writes (C4).
- [x] 4.3 `AddressInput` and `AmountInput` with field-level errors and a typed value (D7, C5). Take the native currency symbol from the chain instead of a hard-coded "ETH" (C10): `nativeCurrency` comes from the chain descriptor; each tab moves to it as it is rebuilt (sections 5–10).
- [x] 4.4 `InlineError`, with Try again and a stale note (C6). Each tab routes every failure through it or a toast, never neither, as it is rebuilt (sections 5–10).
- [x] 4.5 `StatusText`, `TimelockedTag` and `QueuedMarker`; exact values available without a `title` tooltip (C11).
- [x] 4.6 `usePendingOperations`: the timelock's pending operations, read once and shared by the markers and the Overview (N7).
- [x] 4.7 The status line's queued-change count, linking to Timelock, and the block of the last refresh; the Timelock tab's pending count (G1, G2).
- [x] 4.8 Config: optional `explorerUrl` and `addresses` per deployment, validated at load; `TxLink` and `AddressLabel` (*you*, *the timelock*, *the paymaster*, configured labels; a Safe's threshold read once per deployment) (D9, G3, G4).
- [x] 4.9 Vitest as a pinned dev dependency (ABIP-6, ABIP-7, lockfile in its own commit); unit tests for `parseRoute`, the input validators and `useChainAction`'s resolution (G11).

## 5. Tenants

- [x] 5.1 One list joining the registry and the roster by id:
  - search, a state filter, show deleted;
  - balance and deficit;
  - keyboard-reachable rows that open the tenant page (C1, K2, K9).
- [x] 5.2 Tenant page:
  - registry record with a structured policy editor (K11);
  - admin keys, with close guarded until shown-once keys are copied (K11);
  - history with before/after diffs (K10).
- [x] 5.3 Tenant page, on-chain card:
  - register, fund, enable/disable;
  - fee override and withdrawal address, each Send or Propose (N2, N9);
  - other deployments.
- [x] 5.4 Per-tenant activity on the tenant page (N8).
- [x] 5.5 Suspend offers to disable on every chain (K11, spec §11.3); create accepts policy and branding. The follow-up is sent on the selected chain; the other chains where it still applies are named, because a write there needs the console switched to that deployment.
- [x] 5.6 e2e: list, tenant page, register from the page, fee override Send.
- [x] 5.7 Tenant page: wallet-api's ledger compared with the chain, and each other configured chain's registration, enabled state and ledger balance via `/v1/platform/rpc/<chainId>` (G6, D10).
- [x] 5.8 List: users column, the next on-chain step per row (Register on chain, Fund), totals under the list, and the roster-only list where `platformApi` is false.

## 6. Paymaster tab

- [x] 6.1 Move Settings to `/paymaster` as role-labelled cards, using the shared primitives (K4).
- [x] 6.2 Stake lifecycle: add, unlock, withdraw; the unstake delay in human units and unlocking as a date (N1, K1).
- [x] 6.3 Upgrade: the current implementation from the ERC-1967 slot, and Propose `upgradeToAndCall` (N3). The SDK gains `getImplementation` and `upgradeToAndCall`, with a changeset, so a wallet holding `UPGRADER_ROLE` (a devnet) can Send.
- [x] 6.4 Treasury withdraw with Max and confirmation; confirmation on pause, stake unlock and signer removal (C4).
- [x] 6.5 Unpause; clear each input after its write succeeds; validate gas and delays as whole numbers (K4).

## 7. Roles

- [x] 7.1 The role table with timelocked/immediate and "you" badges; flag non-timelock holders of timelocked roles (K3).
- [x] 7.2 Revoke with confirmation. Allow revoking `DEFAULT_ADMIN_ROLE` when held (D4). Only a holder can: it is its own admin. The SDK gains `renounceRole` and a `revokeRole` that takes `DEFAULT_ADMIN_ROLE`, with a changeset. Renounce is offered on the wallet's own roles; the timelock renouncing its own is not offered in this layer, and comes with the Timelock tab's proposals (8.4). Revoking or renouncing the last holder of a role says so, and for `ROLE_ADMIN` that it freezes role management.
- [x] 7.3 "Propose a role change": grant, revoke, and rotate as one batch (N5).
- [x] 7.4 Each role's "may, and may not" from the SDK role table; the `DEFAULT_ADMIN_ROLE` banner; Execute on a ready role change (G8).

## 8. Timelock

- [x] 8.1 SDK: proposal-call helpers for `updateDelay`, `setFunctionDelay` and timelock role grants and revokes, with tests and a changeset (N6).
- [x] 8.2 Operations list:
  - a Pending/Done/Cancelled/All filter;
  - the log window sized to the longest delay;
  - full ids;
  - schedule and execute tx links;
  - read incrementally instead of every window on each poll (K5).
- [x] 8.3 Schedule, execute and cancel sent directly by a PROPOSER, EXECUTOR or CANCELLER wallet; a cancel batch for incomplete operations (N4).
- [x] 8.4 Proposal dialog: multi-call, salt, delay and predecessor; operation id; copy calldata; Safe schedule, execute and cancel batches (N5).
- [x] 8.5 Delays table with Propose change; the timelock's own PROPOSER, CANCELLER and EXECUTOR holders with Propose grant/revoke (N6).
- [x] 8.6 Summary: address, minimum delay, who proposes, cancels and executes (checked against the configured addresses, saying the timelock cannot list them), and what the connected wallet may do (G9).
- [x] 8.7 e2e: schedule from a PROPOSER wallet, execute, cancel, and a rotation batch on the e2e timelock. The baked devnet state has no timelock and the rest of the suite needs admin-console to keep every role, so `timelock-console.spec.ts` deploys its own 2-second GianoTimelock from the v2 release, points the console at it through `/config.json`, and takes back what it grants.

## 9. Overview

- [x] 9.1 Needs attention (more than three of one kind fold into one line naming the first few, each linking to its tenant page):
  - tenants in deficit, unfunded, unregistered, or disagreeing between registry and chain;
  - ready operations;
  - pause state (N10).
- [x] 9.2 Stat cards, solvency, configuration (with the implementation), queued changes; tenants named by slug (K1). The usage card waits for `GET /v1/platform/usage` (B4, task 16) and is absent until then.

## 10. Activity, Health, Admins, docs

- [x] 10.1 Activity:
  - tx links and timestamps;
  - tenant filter and totals;
  - an error state;
  - "Look further back" instead of the 100-row cap;
  - refreshed with everything else without losing the older pages already loaded (K6, C7).
- [x] 10.2 Health: its own icon, a labelled badge, and the subtitle fixed (K7).
- [x] 10.3 Admins: field-level errors; the shared confirm; the note that removing an admin ends their sessions (K12, G12).
- [x] 10.4 README: the tab list, the write rules, and the proposal-builder claim corrected. `specs/PLATFORM-ADMIN-SPECS.md` §11.2 (C12).
- [x] 10.5 Run `openspec validate redesign-paymaster-console --strict` and the full e2e suite. Strict validation passes with openspec 1.9.0, the version used here; later versions also warn that some requirements are long, which `--strict` counts as errors (a follow-up: move their detail into scenarios). Locally, against a long-lived stack: all pass except tenant-isolation V1, which registers a fixed external user id and needs a fresh database, as CI has; BYO specs need the local packages rebuilt first, since Playwright bundles the BYO wallet from them.
- [x] 10.6 Activity: outcome and account filters, the overhead column, and Export CSV of the loaded rows (G5).
- [x] 10.7 Health: checks grouped as Funds, Keys and roles, Registry and chain; the console-side registry and ledger checks; what to do, with a link, on each warning (G7, D10).
- [x] 10.8 Phone width: every tab at 390 px with no page-level horizontal scroll; an e2e case at that size (G10).
- [x] 10.9 e2e: Stay signed in (G11). It caught that a renewed session rebuilt the chain read client and unmounted the page, losing what was typed; the client now reads the session token per request.

## 11. Phase 2: timelock-aware health (B2, layer 12)

- [x] 11.1 Contracts: match `GianoPaymaster`'s code to a release (D13). Done by main's release fingerprints and `releaseOf` (#197), which this layer uses; it adds the shared timelock checks (`timelockedRoleProblems`, `delayShortfalls`, `parseDelayList`). Changeset.
- [x] 11.2 SDK: `assessHealth` takes an optional timelock context; the timelocked-roles and delays checks; the implementation-release check. Replace the "verify this is the timelock" warning. Tests and a changeset.
- [x] 11.3 `giano-doctor chain`: pass the profile's delays and the timelock, and apply the same checks. `contracts:doctor --chain` already passed the profile's timelock, delays and proposers; the doctor now judges them with the SDK's functions (`timelockedRoleProblems`, `delayShortfalls`) and checks the implementation's release.
- [x] 11.4 Console: pass the timelock context and the implementation codehash; Health shows the three checks in Keys and roles. The published delays come from a new optional `timelockDelays` per deployment (D23). e2e: with the test's timelock, and without one.

## 12. Phase 2: admin events (B1, layer 13)

- [ ] 12.1 SDK: `getAdminEvents({ range, kinds })` over the paymaster and timelock, decoded with role names, windowed like `getSponsorships`. Changeset (D12).
- [ ] 12.2 SDK test: every privileged event in the paymaster ABI is decoded.
- [ ] 12.3 Console: Admin events in Activity, with *Look further back*; the tenant page's history adds that tenant's on-chain events.

## 13. Phase 2: sign-ins and sessions (B6, layer 14)

- [ ] 13.1 wallet-api: `lastSignInAt` and `activeSessions` on `GET /v1/platform/admins`; `GET /v1/platform/admins/:id/sessions`; `DELETE /v1/platform/admins/:id/sessions/:sessionId` for your own sessions only (D15). Route tests.
- [ ] 13.2 Console: last sign-in and active sessions on Admins; your own sessions with *End*.

## 14. Phase 2: chains (B3, layer 15)

- [ ] 14.1 wallet-api: the prober keeps its last verification and each probe; `BundlerClient.supportedEntryPoints()`.
- [ ] 14.2 wallet-api: `GET /v1/platform/chains`, probed in parallel with a 3-second timeout, no URLs in the response. Route tests, including one chain down.
- [ ] 14.3 Console: the Chains section on Health, with the head-age and watcher-lag thresholds next to the doctor's.
- [ ] 14.4 Update `specs/PLATFORM-ADMIN-SPECS.md` §10 from "follow-up card" to delivered.

## 15. Phase 2: drift (B5, layer 16)

- [ ] 15.1 wallet-api: drift computed at the end of each watcher pass, held in memory with its time (D14). Unit tests for each kind of drift, and for a watcher that is behind.
- [ ] 15.2 wallet-api: `GET /v1/platform/drift` and the per-chain drifted-tenants metric.
- [ ] 15.3 `giano-doctor`: a drift check.
- [ ] 15.4 Console: Health's Registry and chain group reads the endpoint when it exists (D10, D11).

## 16. Phase 2: usage (B4, layer 17)

- [ ] 16.1 wallet-api: `GET /v1/platform/usage` from `sponsorship_decisions` and `sponsorship_settlements`, at most 90 days, rate limited. Add an index if the query plan needs one, in its own migration.
- [ ] 16.2 Console: the Usage card on the Overview and the tenant page, absent when the endpoint returns 404 (D11).
- [ ] 16.3 Final pass: `openspec validate redesign-paymaster-console --strict`, the full e2e suite, and the README and `PLATFORM-ADMIN-SPECS.md` updated for phase 2.
