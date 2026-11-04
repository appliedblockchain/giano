## Context

The console is a Vite + React 19 + Chakra UI v3 SPA. It reads the chain through the SDK, and through wallet-api's platform relay when the platform API is configured (`gate-paymaster-console-reads`), and writes through the connected wallet. It has two areas:
- **Paymaster:** Overview, Tenants, Roles, Settings, Timelock, History, Health.
- **Platform:** Tenants, Admins, behind a SIWE session.

`App.tsx` held the header, the area switch, the wallet, the tab bar and the proposal dialog in one 629-line component. Layers 1–4 have since replaced it with a shell (`shell/`), a router (`lib/router.tsx`) and the theme; the old panels are mounted unchanged under the new routes.

The A1 assessment produced:
- the keep/change/new list (K1–K12, C1–C12, N1–N10, B1–B6);
- four decisions, D1–D4, all taken as recommended;
- the design canvas.

A second pass (2026-11-02) checked the canvas against the code and the plan, and found the gaps G1–G12 in the proposal. One apparent gap was not one: the canvas's "not on the admin list" wording is already what `platform-console-access` requires for a `401` from verify.

This change covers the whole redesign:
- **Phase 1** (layers 1–11): console only, the K, C, N and G items.
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
The new `useChainAction` hook in `hooks/` replaces the ad-hoc mix of `useWrite` calls and per-panel checks. Given the operation name, it resolves, from the SDK's `TIMELOCKED_OPERATIONS` and the wallet's roles, to one of:
- `send`: the wallet holds the role; sends directly. A timelocked role on a deployment with a timelock still sends directly when the wallet holds it, as on a devnet.
- `propose`: timelocked, a timelock is configured, and the wallet lacks the role; opens the proposal dialog with the call.
- `blocked`: names the role that's missing and, for a timelocked operation with no timelock configured, says so.

`<ActionButton>` renders the three states consistently: Send in brand colour, Propose in `timelock` purple with a clock, and blocked as disabled with the reason. A destructive operation wraps `send` in a confirmation dialog naming the effect.

### D7. Validation at the input
`AddressInput` and `AmountInput` own their parsing:
- an address is checksummed, or 0x plus 40 hex characters;
- an amount goes through `parseEther` and must be above zero, with an optional max.

Each states its error under the field and hands the form a typed value or `undefined`. No `as Address` survives in `pages/`.

### D8. The stack
Each layer is a PR on the one below and leaves the console working:

1. `fix/paymaster-console-bugs`: the six bugs. **Done** (#179).
2. `openspec`: this change (#180).
3. Theme and colour mode (D4, D5). **Done** (#181).
4. Shell: the router, the header, the tab bar, sign-in, the session warning, disconnect (D1, D2). The existing panels are mounted unchanged under the new routes. **Done** (#183).
5. Shared primitives: `ActionButton`, `useChainAction`, `ConfirmDialog`, `AddressInput`, `AmountInput`, `InlineError`, `StatusText`, `QueuedMarker`, `usePendingOperations`, `AddressLabel`, `TxLink` (D6, D7, D9). Config: `explorerUrl` and `addresses`. Vitest. The status line's queued count and block, and the Timelock tab count (G1, G2).
6. Tenants list and tenant page (D3), with the ledger comparison and the other deployments (G6).
7. Paymaster tab: every card, including the stake lifecycle, upgrade, treasury max and unpause.
8. Roles.
9. Timelock: the summary, the operations list, writes, options, batches, self-administration. Includes the SDK helpers and their changeset.
10. Overview dashboard.
11. Activity, Health, Admins, phone width, and the README and spec docs.

Phase 2. Each is an SDK or wallet-api PR, then the console part, which can be the same PR when it is small:

12. B2: timelock-aware `assessHealth`, release codehashes, `giano-doctor`. SDK and contracts changesets.
13. B1: `getAdminEvents` in the SDK, then the admin events in Activity.
14. B6: sign-ins and sessions on the admins endpoints, then the Admins columns.
15. B3: `GET /v1/platform/chains`, the prober and bundler changes, then the Chains section on Health.
16. B5: drift detection, its endpoint, metric and doctor check, then the Registry and chain group on Health.
17. B4: `GET /v1/platform/usage`, then the Usage card on the Overview and the tenant page.

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

### D14. Drift is computed after the watcher syncs
wallet-api's paymaster watcher already reads each paymaster and writes `paymaster_tenants` and `paymaster_state`. Drift detection runs at the end of each watcher pass, compares at the block the watcher reached, and keeps the result in memory with the time it was computed. The endpoint and the metric read that result. No new table, no new job.

### D15. Sign-in history uses the session rows
`platform_admin_sessions` already records start, expiry, revocation, chain, IP and user agent. The last sign-in is the newest `created_at` for the admin; active sessions are those neither expired nor revoked. No migration.

An admin can end only their own sessions. Ending someone else's is already possible by removing them, which is recorded in the admin history; a second, unrecorded way to lock someone out is not worth adding.

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

## Open Questions

- Should the session warning's "Stay signed in" sign a fresh SIWE message, or should wallet-api grow a refresh endpoint? Phase 1 signs again, which needs no backend change.
- B4: refusals are grouped by `SponsorshipRefusalReason`, plus `temporarily-unavailable`. Should a tenant's own sponsorship-rule refusals be split from platform refusals (paused, deficit), so the Overview does not blame the platform for a tenant's rules?
- B5: should drift also be a `/healthz` signal, so a deploy fails on it? This change exposes it; who acts on it is the alerting non-goal.
- B6: is 30 days of session history enough, or does it follow `platform_admin_sessions` retention, whatever housekeeping sets?
- G3: do the `addresses` labels belong in the console config, or in the shared chain descriptor wallet-api also reads? The console config for now; nothing else needs them yet.
