## Why

The paymaster console (`services/paymaster-admin`) grew in three passes: the chain view, the Platform area (H5), and the timelock (G9). Each added tabs without revisiting the whole, and the A1 assessment (2026-10-30) found the result hard to operate:

- **Two views of one tenant.** The Paymaster area shows a tenant by UUID and the Platform area by slug, with no link between them. Registering a tenant that skipped the step at creation means copying its UUID by hand.
- **G9 left holes.** A tenant fee override, a withdrawal address change and an upgrade can't be sent or proposed where they belong. The fee override and the address can only be built in the Timelock tab, so on a deployment without a timelock they can't be done at all. The console never schedules or cancels an operation, and has no stake unlock or withdraw.
- **Inconsistent write rules.** Some controls hide when the wallet lacks the role and others disable. Destructive chain writes such as pause, revoke and treasury withdraw go out in one click. Several inputs are cast to `Address` unvalidated, and some failures are silent.
- **What an operator cannot see at all.** Who changed a role, a fee or the implementation is not readable anywhere. Health warns about timelocked roles even when the timelock holds them. Whether wallet-api can transact on a chain, how much it sponsors, whether its ledger agrees with the chain, and who signed in are all in wallet-api's database with no endpoint.
- **Bugs:** NaN polling, a Timelock spinner that never stops, a wrong `colSpan`, a "PlatformAdmin" header, a session id type that drifted from the API, and swallowed errors.

The design is the Claude Design canvas at https://claude.ai/artifact/JY7yvpeFZpdZGWAC7yVx6W, with custom-example as the visual reference.

## What Changes

This change specifies the whole redesign: phase 1, console-only (the K, C and N items from the assessment, layers 1–11), and phase 2, which needs SDK and wallet-api work (the B items, layers 12–17). It also takes in the gaps found by checking the canvas against the code (the G items below).

### Status (2026-11-02)

| Layer | What | State |
| --- | --- | --- |
| 1 | Six bugs | Done, PR #179 |
| 2 | This change, phase 1 plan | PR #180. The plan's extension to the gaps and phase 2 landed as the first commit of layer 5, to leave #180 unchanged in review. |
| 3 | Theme and colour mode | Done, PR #181 |
| 4 | Shell: router, header, tab bar, sign-in, session warning, disconnect | Done, PR #183 |
| 5 | Shared primitives, config, Vitest, status line counts | Done, PR #184 |
| 6 | Tenants list and tenant page | Done, PR #185 |
| 7 | Paymaster tab | Done, PR #186 |
| 8 | Roles | Done, PR #187 |
| 9 | Timelock | Done, PR #188 |
| 10 | Overview | Done, PR #189 |
| 11 | Activity, Health, Admins, phone width, docs | Done, PR #190 |
| 12 | Phase 2: B2, timelock-aware health | Done, PR #205 |
| 13 | Phase 2: B1, admin events | Done, PR #206 |
| 14 | Phase 2: B6, sign-ins and sessions | Done, PR #207 |
| 15–17 | Phase 2: B3, B5, B4 | To do |

### Phase 1: console only

- **One console, one tab bar.** The Paymaster/Platform area switch goes. The tabs are Overview, Tenants, Paymaster, Roles, Timelock, Activity, Health and Admins. Admins exists only where the platform API is configured. Each tab and each tenant has a URL, so a reload or a shared link lands where it was.
- **BREAKING (console UX):** the Settings tab becomes Paymaster, History becomes Activity, and the tenant drawer becomes a tenant page.
- **One tenant.** A single list joins the registry and the on-chain roster by tenant id, shown by slug. Each tenant has a page with its registry record, its on-chain state on the selected chain, its other deployments, its activity, and every action on both halves: register, fund, fee override, withdrawal address, enable/disable, edit, suspend, resume, delete, keys.
- **One rule for every write:**
  - A control the wallet can't use is shown disabled and names the missing role.
  - A timelocked action offers **Send** when the wallet holds the role, and **Propose** when a timelock is configured, in context.
  - Destructive chain writes ask for confirmation.
  - Inputs are validated before they reach the wallet.
  - Failures are shown inline.
- **Timelock completeness:**
  - schedule, execute and cancel, sent from a PROPOSER, EXECUTOR or CANCELLER wallet;
  - salt, delay and predecessor options;
  - multi-call batches, for role rotation;
  - `updateDelay`, `setFunctionDelay` and timelock role proposals;
  - "change queued" markers on the tenant, setting or role they will change.
- **Paymaster completeness:** stake unlock and withdraw; upgrade proposals with the current implementation read from the ERC-1967 slot; treasury withdraw with "max"; pause and unpause.
- **Overview as a dashboard:** what needs attention, queued changes, solvency, and configuration.
- **Look:** custom-example's theme: system font, indigo brand, emerald accent, the zinc neutrals. Timelocked actions are purple with a clock. Light and dark, with a toggle.
- **Session:** a warning two minutes before the platform admin session ends, with a way to sign again in place.

### Gaps found against the canvas and the code

These were in the canvas, or are needed to build it, but were in neither the assessment list nor the phase 1 plan:

- **G1 · Status line:** the queued-change count, linking to Timelock, and the block the snapshot was read at. Task 3.2 was ticked without them; they need `usePendingOperations` (layer 5).
- **G2 · Tab counts:** the Timelock tab shows the number of pending operations, as Tenants shows its count.
- **G3 · Known addresses.** The canvas names holders ("you", "the timelock", "the Safe · 3 of 5", "on-call"). A timelock cannot list its PROPOSER, CANCELLER or EXECUTOR holders. A new optional `addresses` map in each deployment's config labels addresses, and lists the candidates the console checks timelock roles against. A labelled Safe has its threshold and owner count read from it.
- **G4 · Explorer links.** Activity, the tenant page and the Timelock tab link transactions, but no deployment config has an explorer. A new optional `explorerUrl` per deployment; with none, hashes are shown in full and copyable, without a link.
- **G5 · Activity:** outcome and account filters, the overhead column, and a CSV export of what is loaded.
- **G6 · Tenant page:** wallet-api's ledger compared with the chain (agrees, or the difference and the lag in blocks); registration and enabled state on each other configured chain, read through `/v1/platform/rpc/<chainId>`.
- **G7 · Health, console side:** checks grouped as Funds, Keys and roles, and Registry and chain. The registry-and-chain group adds two checks the console can make now: every on-chain tenant has a registry row, and wallet-api's ledger matches the chain. A registry tenant not yet registered is listed under Needs attention, not as a failed check.
- **G8 · Roles:** each role's "may, and may not" text from the SDK's role table; a banner when `DEFAULT_ADMIN_ROLE` is held by nobody, and a warning when it is held; an Execute control on a role change that is ready.
- **G9 · Timelock summary:** the timelock's address, minimum delay, who proposes, cancels and executes (G3), and what the connected wallet may do on it.
- **G10 · Phone width.** Every page works at 390 px: the header wraps, the tab bar scrolls, and wide tables scroll in their own box.
- **G11 · Tests.** The console has no unit tests. Add Vitest for the router, the input validators, the Send/Propose/blocked resolution and the queued-change matching. Add an e2e case for "Stay signed in".
- **G12 · Admins:** the page says that removing an admin ends their sessions at once, which wallet-api already does.

### Found and fixed in phase 1

Building and testing the layers found these, each fixed in the layer that introduced it or, for older ones, in the layer that found it:

- **A reverted write was announced as confirmed.** The write path waited for the receipt and never read its status. Older than the redesign.
- **SDK writes were sent with the bare gas estimate.** On the devnet that is exactly the post-refund gas used, so a call that clears storage (cancelling an operation) ran out of gas. Writes now carry a fifth more.
- **The tenant edit dialog reset on every poll**, wiping what was typed, because the page re-reads the tenant each refresh.
- **A field was cleared after its write succeeded even when a new value had been typed** while the refresh ran.
- **Stay signed in remounted the page.** The chain read client was keyed on the session token, so a renewed session rebuilt it and unmounted whatever was open.
- **A reopened Issue key dialog showed the last key again.**
- **The create dialog's Register on-chain blamed the role** when the withdrawal address was merely empty.
- **The sticky header covered controls** scrolled to after a dialog closed, and keyboard focus with them.
- **The tab bar and the tenant list counted tenants differently**: the roster against the registry.

### Phase 2: SDK and wallet-api

- **B1 · Admin events.** The SDK reads the paymaster's and the timelock's privileged events into one decoded, windowed list, and the Activity tab shows it beside the settlements.
- **B2 · Timelock-aware health.** `assessHealth` and `giano-doctor` check that the timelocked roles are held by the timelock only, that its delays are at or above the published values, and that the implementation's codehash matches a known release.
- **B3 · Chains.** `GET /v1/platform/chains`, as specified in `specs/PLATFORM-ADMIN-SPECS.md` §10.2, and a Chains section on the Health tab.
- **B4 · Usage.** `GET /v1/platform/usage`: sponsored and refused operations, refusals by reason, gas sponsored and fees, across tenants and per tenant, for a time range. A Usage card on the Overview and the tenant page.
- **B5 · Drift.** wallet-api compares its ledger and registry with each paymaster's roster, reports the result at `GET /v1/platform/drift` and as a metric, and `giano-doctor` checks it. The Health tab's registry-and-chain group reads it.
- **B6 · Sign-ins.** `GET /v1/platform/admins` gains each admin's last sign-in and active session count. `GET /v1/platform/admins/:id/sessions` lists recent sessions, and an admin can end any of their own.

### Non-goals

- Tenant self-service through `/v1/admin/*` (D1). Sponsorship rules, transaction mappings and passkey origins stay with the tenant's admin key.
- Withdrawing a tenant's balance from the console (D3).
- A brand pass. The theme's values are custom-example's placeholders until the Applied Edge Design System tokens land.
- Alerting on chain status, usage or drift. B3–B5 expose the data; who is paged is out of scope.

## Capabilities

### New Capabilities

- `paymaster-console`: the console's navigation, header, theme and layout, the rules every write follows, and what each tab offers.
- `paymaster-admin-events` (B1): the SDK's decoded list of privileged paymaster and timelock events.
- `paymaster-health-checks` (B2): the checks `assessHealth` and `giano-doctor` apply, including the timelock-aware ones.
- `platform-chain-status` (B3): `GET /v1/platform/chains`.
- `platform-usage-metrics` (B4): `GET /v1/platform/usage`.
- `tenant-chain-drift` (B5): server-side drift detection between wallet-api and the chain.

### Modified Capabilities

- `platform-console-access`: the Platform area switch is replaced by tabs that exist only where the platform API is configured, and the session warns before it ends.
- `platform-console-tenants`: the registry and the roster become one tenant list, and the drawer becomes a tenant page with the on-chain actions, the ledger comparison and the other deployments.
- `platform-admin-management` (B6): admins are listed with their last sign-in and active sessions, and an admin can see and end their own sessions.

## Impact

- **paymaster-admin:**
  - `App.tsx` split into a shell (`shell/`) and routes; the old `panels/` are gone, replaced by a folder per tab: `overview/`, `tenants/`, `paymaster/`, `roles/`, `timelock/`, `activity/`, `health/`. `platform/` keeps the sign-in, Admins and the tenant dialogs.
  - `components/` holds the shared primitives; `lib/` their pure logic, unit-tested.
  - `config.ts`: optional `explorerUrl`, `addresses` and `nativeCurrency` per deployment (G3, G4).
  - A small in-house router; no new runtime dependency. Vitest as a dev dependency (G11), pinned under ABIP-6 and ABIP-7.
- **paymaster-sdk**, each with a changeset:
  - phase 1: `getImplementation` and `upgradeToAndCall` (layer 7); `renounceRole`, and `revokeRole` taking `DEFAULT_ADMIN_ROLE` (layer 8); `timelockCall`, the proposals for `updateDelay`, `setFunctionDelay` and the timelock's own roles, and `cancelCalldata` (layer 9); gas headroom on every write (layer 9, a fix);
  - phase 2: `getAdminEvents` (B1) and timelock-aware `assessHealth` (B2).
- **contracts:** release codehashes exported for `assessHealth` (B2). No contract change.
- **wallet-api:** three new platform endpoints (`chains`, `usage`, `drift`), sessions on the admins endpoints (B6), the prober and bundler changes §10.2 names, and a drift metric. No schema migration except an index if usage queries need one.
- **e2e:** `paymaster-admin.spec.ts`, `platform-console.spec.ts` and `platform-admin.spec.ts` follow each layer, with new cases for the tenant page, the Paymaster and Roles tabs, the Overview, Stay signed in and phone width. `timelock-console.spec.ts` (new) deploys its own timelock for the schedule, execute, cancel and rotation cases. Phase 2 adds cases for its endpoints.
- **Docs:**
  - the console README: its tab list, the write rules, the config fields, and the claim of "a proposal builder for every timelocked action";
  - `specs/PLATFORM-ADMIN-SPECS.md` §10 and §11.2.
