## 1. Bugs (`fix/paymaster-console-bugs`)

- [x] 1.1 Refuse a `refreshSeconds` that isn't a non-negative number at config load, instead of polling with `setInterval(NaN)`.
- [x] 1.2 Timelock tab: after a failed first read, show "Nothing to show" with Try again instead of a spinner that never stops.
- [x] 1.3 Registry table: `colSpan` 6 on the empty row, matching the six columns.
- [x] 1.4 Admins table: rename the "PlatformAdmin" column header to "Admin"; remove the stray `console.log` calls.
- [x] 1.5 Rename `HistoryEntry.platformSessionId` to `platformAdminSessionId`, as wallet-api returns it.
- [x] 1.6 Show the error when the Fund amount doesn't parse, when the deleted-tenants read fails, and when the drawer's history read fails.

## 2. Theme

- [ ] 2.1 Replace `theme.ts`:
  - the system font stack, plus the `brand` and `accent` palettes with light and dark semantic tokens, as in custom-example;
  - a white `canvas`;
  - the `timelock` semantic palette (D5).
- [ ] 2.2 Add colour mode: the `.dark` class on `<html>`, a hook, and an inline pre-paint script in `index.html` (D4). Add a toggle in the header.
- [ ] 2.3 Check every existing panel in light and dark mode on the e2e stack, and fix any hard-coded colour.

## 3. Shell and navigation

- [ ] 3.1 Add `lib/router.tsx`: `useRoute`, `navigate`, `<Link>`, the route table, and an unknown-route view (D1).
- [ ] 3.2 Split `App.tsx` into `shell/Header.tsx` and `shell/TabBar.tsx`, a route outlet, and the existing connect and deployment logic.
  - The header: logo, title, deployment select, paymaster address, session pill, wallet with disconnect, colour-mode toggle.
  - The status line: health level, invariant, queued count, last refresh.
- [ ] 3.3 One tab bar: Overview, Tenants, Paymaster, Roles, Timelock, Activity, Health, Admins. Admins only with `platformApi`. Remove the area switch (D2). Mount the existing panels under their new routes unchanged.
- [ ] 3.4 The sign-in page at `/sign-in` with its steps. After sign-in, return to the route that asked for it.
- [ ] 3.5 The session warning two minutes before expiry, with Stay signed in (a fresh signature) and Sign out (K8).
- [ ] 3.6 Wallet disconnect. Take the native currency symbol from the chain instead of a hard-coded "ETH" (C10).
- [ ] 3.7 Pause polling while the tab is hidden. Refresh Activity and the registry with everything else (C7).
- [ ] 3.8 e2e: move the console specs to the new tab names and routes; add a deep-link case and an unknown-route case.

## 4. Shared primitives

- [ ] 4.1 `useChainAction` and `<ActionButton>`: send, propose or blocked, with the missing role named (D6, C2, C3).
- [ ] 4.2 `ConfirmDialog` for destructive writes (C4).
- [ ] 4.3 `AddressInput` and `AmountInput` with field-level errors and a typed value (D7, C5).
- [ ] 4.4 `InlineError`. Route every failure through it or a toast, never neither (C6).
- [ ] 4.5 `StatusText`, `TimelockedTag` and `QueuedMarker`; exact values available without a `title` tooltip (C11).
- [ ] 4.6 `usePendingOperations`: the timelock's pending operations, read once and shared by the markers and the Overview (N7).

## 5. Tenants

- [ ] 5.1 One list joining the registry and the roster by id:
  - search, a state filter, show deleted;
  - balance and deficit;
  - keyboard-reachable rows that open the tenant page (C1, K2, K9).
- [ ] 5.2 Tenant page:
  - registry record with a structured policy editor (K11);
  - admin keys, with close guarded until shown-once keys are copied (K11);
  - history with before/after diffs (K10).
- [ ] 5.3 Tenant page, on-chain card:
  - register, fund, enable/disable;
  - fee override and withdrawal address, each Send or Propose (N2, N9);
  - other deployments.
- [ ] 5.4 Per-tenant activity on the tenant page (N8).
- [ ] 5.5 Suspend offers to disable on every chain (K11, spec §11.3); create accepts policy and branding.
- [ ] 5.6 e2e: list, tenant page, register from the page, fee override Send.

## 6. Paymaster tab

- [ ] 6.1 Move Settings to `/paymaster` as role-labelled cards, using the shared primitives (K4).
- [ ] 6.2 Stake lifecycle: add, unlock, withdraw; the unstake delay in human units and unlocking as a date (N1, K1).
- [ ] 6.3 Upgrade: the current implementation from the ERC-1967 slot, and Propose `upgradeToAndCall` (N3).
- [ ] 6.4 Treasury withdraw with Max and confirmation; confirmation on pause and on signer removal (C4).

## 7. Roles

- [ ] 7.1 The role table with timelocked/immediate and "you" badges; flag non-timelock holders of timelocked roles (K3).
- [ ] 7.2 Revoke with confirmation. Allow revoking `DEFAULT_ADMIN_ROLE` when held (D4).
- [ ] 7.3 "Propose a role change": grant, revoke, and rotate as one batch (N5).

## 8. Timelock

- [ ] 8.1 SDK: proposal-call helpers for `updateDelay`, `setFunctionDelay` and timelock role grants and revokes, with tests and a changeset (N6).
- [ ] 8.2 Operations list:
  - a Pending/Done/Cancelled/All filter;
  - the log window sized to the longest delay;
  - full ids;
  - schedule and execute tx links;
  - read incrementally instead of every window on each poll (K5).
- [ ] 8.3 Schedule, execute and cancel sent directly by a PROPOSER, EXECUTOR or CANCELLER wallet; a cancel batch for incomplete operations (N4).
- [ ] 8.4 Proposal dialog: multi-call, salt, delay and predecessor; operation id; copy calldata; Safe schedule, execute and cancel batches (N5).
- [ ] 8.5 Delays table with Propose change; the timelock's own PROPOSER, CANCELLER and EXECUTOR holders with Propose grant/revoke (N6).

## 9. Overview

- [ ] 9.1 Needs attention:
  - tenants in deficit, unfunded, unregistered, or disagreeing between registry and chain;
  - ready operations;
  - pause state (N10).
- [ ] 9.2 Stat cards, solvency, configuration (with the implementation), queued changes; tenants named by slug (K1).

## 10. Activity, Health, Admins, docs

- [ ] 10.1 Activity:
  - tx links and timestamps;
  - tenant filter and totals;
  - an error state;
  - "Look further back" instead of the 100-row cap (K6).
- [ ] 10.2 Health: its own icon, a labelled badge, and the subtitle fixed (K7).
- [ ] 10.3 Admins: field-level errors; the shared confirm (K12).
- [ ] 10.4 README: the tab list, the write rules, and the proposal-builder claim corrected. `specs/PLATFORM-ADMIN-SPECS.md` §11.2 (C12).
- [ ] 10.5 Run `openspec validate redesign-paymaster-console --strict` and the full e2e suite.
