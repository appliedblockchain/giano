## Context

The console is a Vite + React 19 + Chakra UI v3 SPA. It reads the chain through the SDK, and through wallet-api's platform relay when the platform API is configured (`gate-paymaster-console-reads`), and writes through the connected wallet.

Before this change it had two areas, **Paymaster** (Overview, Tenants, Roles, Settings, Timelock, History, Health) and **Platform** (Tenants, Admins, behind a SIWE session), with `App.tsx` holding the header, the area switch, the wallet, the tab bar and the proposal dialog in one 629-line component. Phase 1 (layers 1–11, PRs #179–#190) replaced all of it: one tab bar with a page per tab, a shell, the shared primitives, and a folder per tab. None of the old panels remain.

The A1 assessment produced:
- the keep/change/new list (K1–K12, C1–C12, N1–N10, B1–B6);
- four decisions, D1–D4, all taken as recommended;
- the design canvas.

A second pass (2026-11-02) checked the canvas against the code and the plan, and found the gaps G1–G12 in the proposal. One apparent gap was not one: the canvas's "not on the admin list" wording is already what `platform-console-access` requires for a `401` from verify.

This change covers the whole redesign:
- **Phase 1** (layers 1–11): console only, the K, C, N and G items. Done.
- **Phase 2** (layers 12–17): the B items, each an SDK or wallet-api change, followed by the console part that uses it.

## Goals / Non-Goals

**Goals:**
- One navigation, one tenant identity, and one rule each for gating, proposing, confirming, validating and reporting a write.
- Every timelocked paymaster operation can be sent or proposed in context, and every timelock operation can be scheduled, executed or cancelled from the console.
- An operator can see who changed what, whether the deployment can transact, how much it sponsors, and whether wallet-api agrees with the chain, without leaving the console.
- Delivered as a stack of small PRs that each leave the console working.

**Non-Goals:**
- Alerting on chain status, usage or drift: B3–B5 expose the data, and who is paged is decided elsewhere.
- Tenant self-service (D1).
- A tenant-balance withdraw (D3).
- A brand pass: the theme's values are custom-example's placeholders until the Applied Edge Design System tokens land, and swapping them later must touch only `theme.ts`.

## Decisions

### D1. Path routing with an in-house router, no dependency
Routes:
- `/` (Overview);
- `/tenants` and `/tenants/<slug-or-id>`;
- `/paymaster`, `/roles`, `/timelock`, `/activity`, `/health`, `/admins`.

There is no sign-in route. Without a session, the sign-in page is shown in place of whatever path was opened, and signing in renders that path. So a reload, a shared link and a deep link all land where they point.

The router is about 60 lines over `history.pushState` and `popstate`, with a `<Link>` that renders a real `<a href>`, so the browser's own open-in-new-tab and copy-link work.

Why:
- Paths rather than hashes, because nginx already falls back to `index.html` for unknown paths. `/api`, `/rpc`, `/assets` and `/config.json` are not route names.
- Not react-router: it is a large dependency for eight flat routes and one parameter, and ABIP-6/7 make every dependency a reviewed, pinned, release-aged addition.

The deployment stays in `localStorage`, not in the URL. A shared link opens on the receiver's own selected deployment. Putting the deployment in the URL would let a link silently switch someone onto another chain, which is the accident `config.ts` is built to prevent.

### D2. Tenants and Admins are tabs, not an area
The Platform area switch goes. When `platformApi` is false:
- the Tenants tab is built from the on-chain roster alone, by id, as the Paymaster-area Tenants tab is today;
- the Admins tab is absent.

When `platformApi` is true, the Tenants tab joins the registry to the roster by tenant id.

The session gate stays where `gate-paymaster-console-reads` put it: before any chain read.

### D3. A tenant page, not a drawer
A drawer can't hold the on-chain card, other deployments, activity, keys and history without becoming a scrolling page anyway. A page:
- gets a URL (D1);
- leaves the list's filters intact on Back.

### D4. Hand-rolled colour mode
Dark mode is the `.dark` class on `<html>`, which Chakra v3's `_dark` conditions already target. A 30-line hook:
- reads `localStorage`, falling back to `prefers-color-scheme`;
- sets the class before first paint, from `public/color-mode.js`, loaded synchronously in `<head>`. Not an inline script, because the console's CSP is `script-src 'self'`.

custom-example uses `next-themes` for this. It is not worth a dependency for the console.

### D5. Theme tokens
The theme follows custom-example:
- the system font stack, not Inter, because custom-example dropped the webfont;
- the indigo `brand` and emerald `accent` palettes;
- Chakra's default `gray`, which is the zinc scale the canvas uses.

New semantic palettes:
- **`timelock`** (purple: `fg` #7e22ce, `subtle` #faf5ff, `muted` #e9d5ff), for everything that waits on the timelock.
- **`phase2`**: not a token. The canvas tags phase 2 items; the console shows them only once their endpoint exists (D11), so it never needs the tag.

`canvas` becomes white in light mode. The header and table heads use `bg.subtle`.

### D6. One write path
`useChainAction` and `<ActionButton>` replace the ad-hoc mix of `useWrite` calls and per-panel checks. A write names its target, and `resolveAction` (`lib/actions.ts`, unit-tested) resolves it for the wallet in front of it:
- **a timelocked operation** (from the SDK's `TIMELOCKED_OPERATIONS`): `send` when the wallet holds its role, even where a timelock is configured, as on a devnet; `propose` when it does not and a timelock is configured, which opens the proposal dialog with the call and needs no wallet; otherwise `blocked`, naming the role and that no timelock is configured;
- **a role** for an immediate write: `send` or `blocked`, naming the role;
- **anyone with a wallet**, for funding a tenant;
- **a gate** the caller decides, with its own reason, for rules outside the paymaster's role table: holding `DEFAULT_ADMIN_ROLE`, or one of the timelock's own roles.

With no wallet connected, anything but a proposal is `blocked` with "Connect a wallet".

`<ActionButton>` renders the states consistently: Send in brand colour, Propose in `timelock` purple with a clock, blocked as disabled with the reason beneath. A destructive write asks first in a `ConfirmDialog` naming its effect. A *quiet* style (a gray ghost button) marks an action that sits beside a louder one and must not be mistaken for it, as Renounce beside Revoke.

`useWrite` announces *submitted* when the wallet returns the hash and *confirmed* only when the receipt's status is success; a reverted receipt is a failure, with the transaction hash.

### D7. Validation at the input
`AddressInput`, `AmountInput`, `WholeNumberInput` and `CalldataInput` own their parsing (`lib/validate.ts`, unit-tested):
- an address is `0x` plus 40 hex characters, checksummed when mixed-case, and handed on checksummed;
- an amount is a positive decimal in the selected chain's native currency (`parseUnits` with its decimals), with an optional maximum that *Max* fills exactly; 0 only where it is a value (a fee, or Add stake on locked stake);
- a whole number is non-negative, capped where the contract's type is (`uint32` for the post-op gas allowance and the unstake delay), and the penalty at 5000 basis points;
- calldata is `0x` and whole bytes.

Each states its problem under the field as it is typed and hands the form a typed value or `undefined`, so no write casts a string. A field is cleared after its write succeeds only if it still holds what was sent: whatever was typed while the refresh ran belongs to the operator.

### D8. The stack
Each layer is a PR on the one below and leaves the console working:

1. `fix/paymaster-console-bugs`: the six bugs. **Done** (#179).
2. `openspec`: this change (#180). Its extension to the gaps and phase 2 is the first commit of layer 5.
3. Theme and colour mode (D4, D5). **Done** (#181).
4. Shell: the router, the header, the tab bar, sign-in, the session warning, disconnect (D1, D2). The existing panels are mounted unchanged under the new routes. **Done** (#183).
5. Shared primitives: `ActionButton`, `useChainAction`, `ConfirmDialog`, `AddressInput`, `AmountInput`, `InlineError`, `StatusText`, `QueuedMarker`, `usePendingOperations`, `AddressLabel`, `TxLink` (D6, D7, D9). Config: `explorerUrl` and `addresses`. Vitest. The status line's queued count and block, and the Timelock tab count (G1, G2). **Done** (#184).
6. Tenants list and tenant page (D3), with the ledger comparison and the other deployments (G6). **Done** (#185).
7. Paymaster tab: every card, including the stake lifecycle, upgrade, treasury max and unpause. **Done** (#186).
8. Roles. **Done** (#187).
9. Timelock: the summary, the operations list, writes, options, batches, self-administration. Includes the SDK helpers and their changeset. **Done** (#188).
10. Overview dashboard. **Done** (#189).
11. Activity, Health, Admins, phone width, and the README and spec docs. **Done** (#190).

Phase 2. Each is an SDK or wallet-api PR, then the console part, which can be the same PR when it is small:

12. B2: timelock-aware `assessHealth`, release codehashes, `giano-doctor`. SDK and contracts changesets. **Done** (#205).
13. B1: `getAdminEvents` in the SDK, then the admin events in Activity and on the tenant page. **Done** (#206).
14. B6: sign-ins and sessions on the admins endpoints, then the Admins columns and your sessions. **Done** (#207).
15. B3: `GET /v1/platform/chains`, the prober and bundler changes, then the Chains section on Health. **Done** (#208).
16. B5: drift detection, its endpoint, metric and doctor check, then the Registry and chain group on Health.
17. B4: `GET /v1/platform/usage`, then the Usage card on the Overview and the tenant page.

A bug found in a later layer is fixed on the branch of the layer that introduced it, and the layers above are restacked (`gh stack rebase --upstack`), so each PR stays correct on its own: the edit-dialog reset found by CI on #186 was fixed in #185, and an unformatted test in #187 in #187. A bug older than the redesign is fixed, as its own commit, in the layer that found it.

Layers 3–5 are the base: everything above them uses their primitives. Layers 6–11 are independent of each other and can be reordered. Phase 2 layers depend only on layer 11 for the tab they extend, and on nothing in each other; they are ordered by what they are worth against what they cost. They can leave this stack and become their own once phase 1 merges.

### D9. Known addresses and the explorer are configuration
Two things the canvas shows have no source today:
- **Names for addresses.** A timelock built on OpenZeppelin's `AccessControl` cannot enumerate its role holders, so the console cannot discover the Safe that proposes. Each deployment's config gains an optional `addresses` map: `{ "<address>": { "label": "Safe", "kind": "safe" } }`. Labels are shown wherever the address appears, and every configured address is one of the candidates the Timelock tab checks `hasRole` against. `kind: "safe"` makes the console read `getThreshold()` and `getOwners()` from it.
- **An explorer.** An optional `explorerUrl` per deployment. Without one, hashes are shown in full and copyable, which is what a devnet needs.

Both are optional, so every existing config stays valid. Both are validated at load, like `refreshSeconds`.

Why configuration rather than discovery: scanning `RoleGranted` logs would find the holders, but only within the log window the relay allows, and silently miss older grants. A configured list that is checked live is the same answer the runbook already gives.

### D10. Console-side checks first, server-side later
The ledger comparison on the tenant page (G6) and the Health tab's Registry and chain group (G7) are computed in the console in phase 1, from the tenant detail's `ledger` and a chain read. They are approximate: the console compares at whatever block it read, and does not know the watcher's lag except from `lastSyncedBlock`.

B5 moves the comparison into wallet-api, where the watcher's block is known. When `GET /v1/platform/drift` exists, the console uses it and drops its own comparison for Health. The tenant page keeps its own, because it reads the chain anyway.

### D11. The console finds phase 2 endpoints by asking
The console and wallet-api deploy separately, so a console can meet a wallet-api without a phase 2 endpoint. The console calls each one and treats `404` as "not available": the section that needs it is absent, not a placeholder and not an error. Any other failure is shown as a failed read.

`getAdminEvents` is an SDK method, so it is available whenever the console's SDK is new enough. That needs no detection.

### D12. Admin events are a window, like settlements
`getAdminEvents` reads logs in the same windows as `getSponsorships`, so it inherits the relay's log-query bounds and the "Look further back" model. An indexer would answer "every grant ever" in one call, but it is a new service; R-47 asks only that the history be reconstructible from events, which a window that can keep going back satisfies.

The SDK decodes from the paymaster and timelock ABIs it already has. A test fails when the paymaster ABI has a privileged event that the decoder does not handle, so the list cannot fall behind a contract release silently.

### D13. A release is identified by its runtime codehash
`releases/<version>/release.json` holds sources and creation code, not runtime code, so an implementation cannot be matched to it today. The contracts build gains a step that records `GianoPaymaster`'s runtime codehash in each release, and the contracts package exports the map. `assessHealth` takes the implementation's codehash, which the SDK reads with `eth_getCode` through the relay, and looks it up.

Immutable variables in the runtime code would make the hash differ per deployment. `GianoPaymaster` is `UUPSUpgradeable`, whose `__self` immutable holds the implementation's own address, so the recorded hash is computed with the immutable positions zeroed, and the SDK zeroes the same positions before hashing.

As built: the per-chain-contract-addresses change (#197, on main first) built exactly this for every contract a release carries: `release-fingerprints.ts` (generated by `gen:releases`, drift-checked in CI) holds each release's fingerprint, the keccak256 of the runtime code with every immutable range masked, and `releaseOf(contract, code, address)` in `release-code.ts` matches code against them and checks every UUPS `__self` range holds the address the code was read from. `assessHealth` calls `releaseOf("GianoPaymaster", code, address)`; this change records nothing of its own. (`GianoPaymaster`'s two masked ranges are both references to UUPS's `__self`; `EIP712Upgradeable` keeps its domain in storage.)

The judgement itself lives in the contracts package beside the policy: `timelockedRoleProblems` and `delayShortfalls` in `timelock.ts`, and `releaseOf`. The SDK's `assessHealth` and `giano-doctor` both call them, which is how the two "run the same checks" without the doctor importing the SDK (the SDK depends on the contracts package).

### D14. Drift is computed after the watcher syncs
wallet-api's paymaster watcher already reads each paymaster and writes `paymaster_tenants` and `paymaster_state`. Drift detection runs at the end of each watcher pass, compares at the block the watcher reached, and keeps the result in memory with the time it was computed. The endpoint and the metric read that result. No new table, no new job.

### D15. Sign-in history uses the session rows
`platform_admin_sessions` already records start, expiry, revocation, chain, IP and user agent. The last sign-in is the newest `created_at` for the admin; active sessions are those neither expired nor revoked. No migration.

An admin can end only their own sessions. Ending someone else's is already possible by removing them, which is recorded in the admin history; a second, unrecorded way to lock someone out is not worth adding.

As built: sessions are matched to an admin by address, as a session is resolved, not by the id recorded at sign-in (an id can be reused after removal; the address is who signed). The list marks the caller's own session `current`, so the console can offer *End* on every open session but the one it is using. Where a session was signed from (the user agent) is returned only for the caller's own sessions: another admin's show when, not where, which is enough to see that someone signed in and keeps one admin's locations from every other (raised in review of #184). The IP is not returned at all: wallet-api sets no `trustProxy`, so behind the console's nginx every session records the proxy's address, which beside a stolen session would read as the admin's own (raised in review of #207). Carrying the real client IP is a follow-up: turning on `trustProxy` also changes the rate-limit keys of wallet-web's routes, and needs the ALB → nginx → wallet-api hops counted exactly. Ending a session already ended, or expired, is `204` and changes nothing, and ending another admin's by naming yourself is `404`, since that session is not one of yours.

### D16. One console context
`shell/ConsoleContext.tsx` provides what every primitive needs about the console around it: the deployment, the wallet and its paymaster roles, the paymaster address, the timelock client, the `propose` callback, the console refresh and the block it read at, the timelock's operations and access (D17), and each configured Safe's threshold. A control deep in a tab reads it with `useConsole()` instead of having half a dozen props threaded down to it. The paymaster overview and the joined tenant rows stay props: they are what a tab renders, not what a control decides with.

### D17. The timelock is read once, then incrementally
`usePendingOperations` reads the timelock's operations once per console refresh for the whole console: the Timelock tab, its count in the tab bar, the status line, the queued markers, the Roles tab's Execute and the Overview all use the same list. The first read goes back enough windows to cover the longest delay, from the chain's recent seconds per block, never fewer than five and at most 40; it waits for the delays to be known. Each later refresh reads only the blocks after the last one, forward a window at a time to the head, so a long gap that a node or wallet-api's relay narrows is still read whole, merges what they say into what is known (an operation keeps the calls and salt it was scheduled with and takes its new state), and asks the contract for the state of anything still pending, since waiting becomes ready with time alone. *Look further back* adds an older window and never re-reads; it waits for a poll in flight rather than racing it. Reorgs are not handled: a block read once is not read again, so an operation in a block later reorged out stays listed until the page reloads. Its state is re-read from the contract on every refresh, and that is what Execute and the markers go by.

`useTimelockAccess` reads the timelock's config and whether the wallet holds PROPOSER, CANCELLER or EXECUTOR once per timelock and wallet, and again after an Execute, not per refresh: changing either is itself a timelocked operation.

### D18. Needs attention folds what repeats
The Overview's conditions come from a pure `attentionItems` (`lib/attention.ts`). More than three of one kind — twenty tenants with no balance — fold into one line that names the first three, newest first and each a link to its tenant page, and says how many more. Listed one by one they would push the paymaster's own conditions off the page, which is the opposite of what the list is for.

### D19. Phase 1 needed SDK additions
The plan put SDK work in phase 2, but the console's write rules need the SDK to be able to make each write it offers:
- `getImplementation` (the ERC-1967 slot) and `upgradeToAndCall`, so a wallet holding `UPGRADER_ROLE` can Send an upgrade;
- `renounceRole`, and `revokeRole` taking `DEFAULT_ADMIN_ROLE`, which only another holder can revoke;
- `timelockCall`, `proposeUpdateDelay`, `proposeSetFunctionDelay`, `proposeGrantTimelockRole`, `proposeRevokeTimelockRole` and `cancelCalldata` (task 8.1).

Each is its own commit with a changeset. Every SDK write is also sent with a fifth more gas than the node estimates (`withGasHeadroom`), because a bare estimate can be exactly the post-refund gas and a call that clears storage then reverts.

### D20. The session token is read per request
The chain read client is keyed on whether there is a session, not on which. It reads the current token on each request (`fetchFn`), so *Stay signed in* swaps the session without a new client, a re-read or a remount, and whatever the operator was typing stays.

### D21. The e2e timelock is deployed by the test
The e2e devnet's baked state has no timelock, and the rest of the suite needs `admin-console` to keep every paymaster role. Regenerating the baked state needs the pinned anvil and changes a 1 MB file every suite loads. So `timelock-console.spec.ts` deploys its own 2-second GianoTimelock from the v2 release, with `admin-console` as proposer and canceller and executors open, points the console at it by adding `timelockAddress` to the `/config.json` it fetches, grants it `ROLE_ADMIN` alongside `admin-console`, and takes back everything it grants. Two seconds is waited out in real time; anvil stamps blocks with the wall clock, so no time travel is needed, only a mined block.

### D22. The ledger health check runs on demand
The Health tab's ledger check needs one tenant detail per registered tenant. It runs when the tab opens and when asked, five requests at a time, not on every poll, and a result from the last minute is shown again rather than read again, as the platform API allows 60 requests a session a minute. B5 moves the comparison into wallet-api, where it is one read (D10).

### D23. The console's published delays are configuration
A chain's published delays are in its profile (`deploy/chains/*.json`), which the console cannot read. Each deployment gains an optional `timelockDelays`, the profile's `timelock.delays` in seconds, set flat, as `paymasterAdmin.timelockDelays` in the chain document, or as `GIANO_TIMELOCK_DELAYS` in single-chain mode. It names every delay or none, as `deploy/cli.ts` requires of a profile: a partial list would pass a delay it leaves out as "at or above the published values" (the SDK, given a partial list as the doctor's flag allows, warns and names each one). With it, Health fails a delay below its value as `giano-doctor` does; without it, Health warns that the delays were not compared, and still fails a role change that waits less than what it could bypass. A configured timelock that has not been read yet gives no timelock verdict, rather than "no timelock is configured": the check is shown as still being read, and the no-timelock role checks are left out with it. The same holds for the implementation until its first read; a failed read of either is a warning. Health says "every check passes" only once nothing is still being read, as with the ledger comparison.

### D24. Admin events as built
`getAdminEvents` asks the node for the admin events only (one `eth_getLogs` per contract with the events' topics, and one per EntryPoint stake event filtered on the paymaster as `account`), so a window busy with settlements costs no more. The paymaster emits nothing for `addStake`, `unlockStake` and `withdrawStake` (STAKE_ADMIN_ROLE, not timelocked), so its stake changes are the EntryPoint's `StakeLocked`, `StakeUnlocked` and `StakeWithdrawn` for it; not `Deposited`, which anyone can cause. Each entry carries an `actor`:
- the account the event names (a role change's `sender`, a pause's `account`, an enable's `actor`, a funding's `from`);
- the timelock, for a paymaster event in a transaction where the timelock executed a call to the paymaster (its `CallExecuted` is read for this even when `kinds` leaves it out), and for the timelock's own `MinDelayChange` and `FunctionDelayChange`, which only it can make after its constructor;
- otherwise the contract the transaction was sent to when it was not the emitter (a Safe), or the sender when it was; never the EntryPoint, through which a smart wallet's change comes with no actor here.

A Safe calling the timelock that calls the paymaster so shows the Safe for the timelock's `CallExecuted` and the timelock for the paymaster's event. Block times are one read per distinct block; transactions one read per distinct transaction, only for events that name no actor, so cheap events anyone can emit (a 1-wei `depositFor`) cost no transaction read. Blocks and transactions are each read five at a time, so up to ten requests at once; one that fails leaves its field empty rather than failing the list. A `FunctionDelayChange`'s selector is named as a paymaster function only when its target is the paymaster. The event lists are `PAYMASTER_ADMIN_EVENTS`, `TIMELOCK_ADMIN_EVENTS` and `ENTRYPOINT_ADMIN_EVENTS`, beside lists of the paymaster's and timelock's events that are not admin events and why (settlements, `Initialized`, `CallSalt`); the test fails on an ABI event in neither.

A refresh reads the head and then every block since the newest one read, a window at a time (`readForwardPages`), so no request spans more than a window however long the gap.

On the tenant page the chain's events are listed under the registry's history, not interleaved with it: the registry pages by cursor and the chain by window of blocks, and merging them would order entries wrongly wherever one page ends before the other. `tenantId` keeps the tenant's own events, the timelock calls whose arguments name it, and the `Cancelled` of those operations. The tenant page's window is the same 9,000 blocks as Activity's: the relay refuses a wider `eth_getLogs` span, so a topic filter would shrink responses but not let a page cover more.

### D25. Chain status: thresholds, timeouts and the mock node
The console's thresholds: a head older than 60 seconds warns and 5 minutes fails; a ledger watcher more than 50 blocks behind warns, the line past which wallet-api stops trusting the ledger for a tenant delete (`TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS`' default), and more than 1,000 fails. They sit in `lib/health.ts` beside the SDK's deposit and stake thresholds. The repository's local anvil devnets (31337, 31338) mine only when there is a transaction, so an idle one's head is hours old: there the age is shown and not judged, or every local stack would read as failing.

Each part of a chain's status (head, bundler, signer) gets its own 3 seconds, and every chain is read at once, so the response takes about 3 seconds however many chains are down. A bundler that answers `eth_supportedEntryPoints` with a JSON-RPC error is reachable, with `entryPointSupported: null` (a warning in the console), not unreachable.

The Chains section is read with each console refresh while Health is open; each read probes every chain, inside the session's platform rate limit.

## Risks / Trade-offs

- **[A long stack drifts from main]** → Rebase the stack (`gh stack rebase`) whenever main moves under it. Merge bottom-up as each layer is approved, rather than holding the stack until the top is done.
- **[e2e selectors break with each layer]** → Each layer updates the specs it breaks, in the same PR. No layer is merged with a red e2e run.
- **[In-house router edge cases (base path, trailing slash, unknown route)]** → The console is always served at `/`. Unknown paths render a "no such page" view with a link to Overview. Covered by an e2e case per route.
- **[Merging Tenants changes what an operator without the platform API sees]** → On those deployments, the Tenants tab is the roster-only list it is today. The tenant page shows its on-chain half only.
- **[Reading other chains on the tenant page multiplies relay calls]** → One `getTenant` read per other chain, only on the tenant page, only when it is open. Rate-limited with the rest of the session's reads.
- **[A Safe read on every refresh]** → The threshold and owners change rarely; read them once per deployment selection, and on the refresh control.
- **[Usage queries on a large table]** → Bounded to 90 days, indexed (platform-usage-metrics). If that is still slow, aggregate by day in a later change.
- **[Codehash with immutables zeroed is fragile]** → The positions come from the compiler's `immutableReferences`, recorded with the hash. A test deploys the release and checks the SDK's hash matches.
- **[Phase 2 makes the stack 17 deep]** → Once phase 1 merges, phase 2 layers can each be their own short stack.
- **[A long-lived local e2e stack drifts]** → The console specs restore what they change (fees, roles, the timelock's grants) and use fresh names, so they run repeatedly on one stack. Two things still need a fresh one: `tenant-isolation` V1 registers a fixed external user id, and Playwright bundles the BYO wallet from the local package builds, which must be rebuilt after the packages change. CI starts clean each run.

## Open Questions

Resolved in phase 1: *Stay signed in* signs a fresh SIWE message, with no refresh endpoint, and swaps the session in place (D20).


- B4: refusals are grouped by `SponsorshipRefusalReason`, plus `temporarily-unavailable`. Should a tenant's own sponsorship-rule refusals be split from platform refusals (paused, deficit), so the Overview does not blame the platform for a tenant's rules?
- B5: should drift also be a `/healthz` signal, so a deploy fails on it? This change exposes it; who acts on it is the alerting non-goal.
- B6: is 30 days of session history enough, or does it follow `platform_admin_sessions` retention, whatever housekeeping sets?
- B6 follow-up: ending a session only ever applies to the caller's own, so `:id` in `DELETE /v1/platform/admins/:id/sessions/:sessionId` is always the caller. `DELETE /v1/platform/sessions/:sessionId` would drop the 403 case; left for a later change so this one does not reshape the API again.
- B6 follow-ups from review of #207: carry the admin's real IP (`trustProxy` with the hops counted, see D15); index `platform_admin_sessions` on `(address, created_at)`, as `list()` groups the whole table and `sessions()` filters by an unindexed `address` (a migration, so its own change).
- G3: do the `addresses` labels belong in the console config, or in the shared chain descriptor wallet-api also reads? The console config for now; nothing else needs them yet.
