## Why

The paymaster console (`services/paymaster-admin`) grew in three passes: the chain view, the Platform area (H5), and the timelock (G9). Each added tabs without revisiting the whole, and the A1 assessment (2026-10-30) found the result hard to operate:

- **Two views of one tenant.** The Paymaster area shows a tenant by UUID and the Platform area by slug, with no link between them. Registering a tenant that skipped the step at creation means copying its UUID by hand.
- **G9 left holes.** A tenant fee override, a withdrawal address change and an upgrade can't be sent or proposed where they belong. The fee override and the address can only be built in the Timelock tab, so on a deployment without a timelock they can't be done at all. The console never schedules or cancels an operation, and has no stake unlock or withdraw.
- **Inconsistent write rules.** Some controls hide when the wallet lacks the role and others disable. Destructive chain writes such as pause, revoke and treasury withdraw go out in one click. Several inputs are cast to `Address` unvalidated, and some failures are silent.
- **Bugs:** NaN polling, a Timelock spinner that never stops, a wrong `colSpan`, a "PlatformAdmin" header, a session id type that drifted from the API, and swallowed errors. These are fixed in the PR below this change.

The design is the Claude Design canvas at https://claude.ai/artifact/JY7yvpeFZpdZGWAC7yVx6W, with custom-example as the visual reference.

## What Changes

Phase 1 of the redesign, console-only (the K, C and N items from the assessment). Phase 2 (B1–B6) needs backend or SDK work and gets its own changes.

- **One console, one tab bar.** The Paymaster/Platform area switch goes. The tabs are Overview, Tenants, Paymaster, Roles, Timelock, Activity, Health and Admins. Tenants and Admins exist only where the platform API is configured. Each tab and each tenant has a URL, so a reload or a shared link lands where it was.
- **BREAKING (console UX):** the Settings tab becomes Paymaster, History becomes Activity, and the tenant drawer becomes a tenant page.
- **One tenant.** A single list joins the registry and the on-chain roster by tenant id, shown by slug. Each tenant has a detail page with its registry record, its on-chain state on the selected chain, its other deployments, its activity, and every action on both halves: register, fund, fee override, withdrawal address, enable/disable, edit, suspend, resume, delete, keys.
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
- **Paymaster completeness:** stake unlock and withdraw; upgrade proposals with the current implementation read from the ERC-1967 slot; treasury withdraw with "max".
- **Overview as a dashboard:** what needs attention, queued changes, solvency, and configuration.
- **Look:** custom-example's theme: system font, indigo brand, emerald accent, the zinc neutrals. Timelocked actions are purple with a clock. Light and dark, with a toggle.
- **Session:** a warning two minutes before the platform admin session ends, with a way to sign again in place.

**Non-goals:**
- Tenant self-service through `/v1/admin/*` (D1).
- Withdrawing a tenant's balance from the console (D3).
- The B items: an event audit log, timelock-aware `assessHealth`, the Chains tab, usage metrics, server-side drift detection, sign-in history. The design shows them tagged "Phase 2"; the console does not build placeholders for them.

## Capabilities

### New Capabilities
- `paymaster-console`: the console's navigation, its theme, and the rules every write follows (role gating, Send or Propose, confirmation, validation, inline errors). Also what each tab must offer.

### Modified Capabilities
- `platform-console-access`: the Platform area switch is replaced by tabs that exist only where the platform API is configured; the session warns before it ends.
- `platform-console-tenants`: the registry and the roster become one tenant list, and the drawer becomes a tenant page with the on-chain actions.

## Impact

- **paymaster-admin:**
  - `App.tsx` is split into a shell and routes.
  - `panels/` and `platform/` become `pages/` per tab.
  - `components/ui.tsx` grows the shared primitives.
  - `theme.ts` is replaced.
  - A small in-house router; no new dependency.
- **paymaster-sdk:** small helpers to encode `updateDelay`, `setFunctionDelay` and timelock role grants and revokes as proposal calls; the decoders already exist. It needs a changeset.
- **e2e:** `paymaster-admin.spec.ts`, `platform-console.spec.ts` and `platform-admin.spec.ts` move to the new tab names and the tenant page.
- **Docs:**
  - The console README: its tab list, and the claim of "a proposal builder for every timelocked action".
  - `specs/PLATFORM-ADMIN-SPECS.md` §11.2.
- **No backend or contract change.**
