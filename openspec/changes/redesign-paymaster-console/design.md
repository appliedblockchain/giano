## Context

The console is a Vite + React 19 + Chakra UI v3 SPA. It reads the chain through the SDK, and through wallet-api's platform relay when the platform API is configured (`gate-paymaster-console-reads`), and writes through the connected wallet. It has two areas:
- **Paymaster:** Overview, Tenants, Roles, Settings, Timelock, History, Health.
- **Platform:** Tenants, Admins, behind a SIWE session.

`App.tsx` holds the header, the area switch, the wallet, the tab bar and the proposal dialog in one 629-line component.

The A1 assessment produced:
- the keep/change/new list (K1–K12, C1–C12, N1–N10, B1–B6);
- four decisions, D1–D4, all taken as recommended;
- the design canvas.

This change is phase 1: everything console-only.

## Goals / Non-Goals

**Goals:**
- One navigation, one tenant identity, and one rule each for gating, proposing, confirming, validating and reporting a write.
- Every timelocked paymaster operation can be sent or proposed in context, and every timelock operation can be scheduled, executed or cancelled from the console.
- Delivered as a stack of small PRs that each leave the console working.

**Non-Goals:**
- Backend endpoints: the audit log, the chains endpoint, metrics, drift detection and sign-in history are phase 2.
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
- **`phase2`**: not a token. Phase 2 items are not built (Non-Goals).

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

1. `fix/paymaster-console-bugs`: the six bugs. Already open below this change.
2. `openspec`: this change.
3. Theme and colour mode (D4, D5).
4. Shell: the router, the header, the tab bar, sign-in, the session warning (D1, D2). The existing panels are mounted unchanged under the new routes.
5. Shared primitives: `ActionButton`, `useChainAction`, `ConfirmDialog`, `AddressInput`, `AmountInput`, `InlineError`, `StatusText`, `QueuedMarker` (D6, D7).
6. Tenants list and tenant page (D3).
7. Paymaster tab: Settings, plus stake lifecycle, upgrade and treasury max.
8. Roles.
9. Timelock: writes, options, batches, self-administration. Includes the SDK helpers and their changeset.
10. Overview dashboard.
11. Activity, Health, Admins, and the README and spec docs.

Layers 3–5 are the base: everything above them uses their primitives. Layers 6–11 are independent of each other and can be reordered.

## Risks / Trade-offs

- **[A long stack drifts from main]** → Rebase the stack (`gh stack rebase`) whenever main moves under it. Merge bottom-up as each layer is approved, rather than holding the stack until the top is done.
- **[e2e selectors break with each layer]** → Each layer updates the specs it breaks, in the same PR. No layer is merged with a red e2e run.
- **[In-house router edge cases (base path, trailing slash, unknown route)]** → The console is always served at `/`. Unknown paths render a "no such page" view with a link to Overview. Covered by an e2e case per route.
- **[Merging Tenants changes what an operator without the platform API sees]** → On those deployments, the Tenants tab is the roster-only list it is today. The tenant page shows its on-chain half only.

## Open Questions

- Should the session warning's "Stay signed in" sign a fresh SIWE message, or should wallet-api grow a refresh endpoint? Phase 1 signs again, which needs no backend change.
