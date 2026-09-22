# Giano reference dApp — technical specification

The **how** for the demo whose **what** is [`specs/DEMO-REQUIREMENTS.md`](./DEMO-REQUIREMENTS.md).
Requirements `Rn` and findings `Gn` are defined there. Behavioural scenarios are the delta specs in
`openspec/changes/rebuild-custom-example-demo/specs/`.

---

## Contents

1. [Decisions](#1-decisions)
2. [Architecture of the page](#2-architecture-of-the-page)
3. [Runtime configuration contract](#3-runtime-configuration-contract)
4. [The ledger](#4-the-ledger)
5. [Setup preflight](#5-setup-preflight)
6. [Section-by-section UI](#6-section-by-section-ui)
7. [Guards: lint and bundle scan](#7-guards-lint-and-bundle-scan)
8. [Local origins and e2e](#8-local-origins-and-e2e)
9. [Deployment](#9-deployment)
10. [Traceability](#10-traceability)

---

## 1. Decisions

| # | Decision | Alternatives rejected |
|---|---|---|
| D1 | Vite + React 19 + TypeScript + Chakra UI v3 (`~3.36`), `viem` pinned, `wagmi` + `@tanstack/react-query` for the connector card, RainbowKit for the `giano()` adapter. | MUI (no MCP), Tailwind/shadcn (utility classes are CSS authoring). |
| D2 | Published surface only, enforced by ESLint `no-restricted-imports`; dependency `workspace:^` until H2 publishes, same import path afterwards. | Install from the registry now (blocked on H2). |
| D3 | One provider per chain, built lazily from the runtime chain list plus ad-hoc chains; selecting a chain selects a provider. | Any form of switching. |
| D4 | Identity asserted from granted accounts; disagreement is a persistent violation banner plus a ledger row. | Computing the counterfactual address (not possible through the public surface). |
| D5 | Gas payer declared by the user, attributed from `receipt.paymaster` and the native balance delta; mismatch flagged. In the reference stack, wallet-web serves chain B with `sponsorship: off`. | A per-request opt-out (would be a Giano change in disguise). |
| D6 | `GIANO_CHAINS` JSON rendered into `/config.js` at container start by an `envsubst` shell entrypoint (Baanx's pattern); validated with zod in the browser; keyed RPC only via `/rpc/<chainId>` + `GIANO_RPC_UPSTREAM_<chainId>`. No Node in the image; `secret-manager-client` not used. | Baanx's C entrypoint (its value is a hardened base image Giano does not use). |
| D7 | The ledger is the single record: reducer + `localStorage` per wallet origin, cap 500, JSON export with config and versions. Toasts removed. | Keeping toasts alongside. |
| D8 | Twelve stacked cards with a jump bar and a one-line preflight verdict under the header. UX rules: status = dot + text; one action picker per card; outcomes as folded rows, latest open; secondary controls as ghost buttons; provider options in a closed disclosure. | A sidebar/one-section-at-a-time layout; dark instrument look; editorial look (all sketched and set aside). |
| D9 | Claude Design brief and canvas: `https://claude.ai/artifact/P9yQDUV8wsi1rbJmHgZUrF`. | — |
| D10 | Brand in `src/theme.ts` only; `colorPalette="brand"` everywhere else; system font stack. Lint forbids stylesheets, the `css` prop and `style` attributes. | Google Fonts (two CSP origins for nothing). |
| D11 | Demo on `demo.localhost` / `demo-byo.localhost` (4410/4411); both tenants allow-list them alongside the fixture's origins. | Sharing the fixture's ports (the historic clash). |
| D12 | Test ERC-20 deployed with the Ignition `Testing` module, `--strategy create2`, on each testnet; address recorded in the contracts registry. | A per-chain address table in the demo. |
| D13 | `DEVELOPER-GUIDE.md` §3/§4 and `INTEGRATION.md` §9 snippets are lifted from the demo and reference its files. | — |
| D14 | Setup preflight at load (§5). | Documenting the timeouts harder. |

## 2. Architecture of the page

```
src/
  config.ts            runtime config schema (zod) + loader; connector version constant
  theme.ts             the only place brand appears
  lib/chains.ts        ChainRegistry: one provider + public client per chain, provider options, ad-hoc chains
  lib/run.ts           runAction: opens a ledger entry, balances before/after, typed error, payer attribution
  lib/ledger.ts        LedgerEntry, reducer, persistence, export
  lib/errors.ts        describeError: connector error classes → ErrorRecord with meaning and action
  lib/preflight.ts     the six checks
  lib/receipt.ts       UserOpReceipt type, attributePayer
  state/store.tsx      DemoProvider: ledger, sessions per chain, selected chain, violations, preflight, reconnect prompt
  components/primitives.tsx   SectionCard, StatusText, OutcomeRow, ActionPicker, Disclosure, JumpBar, KeyValues
  components/*Card.tsx        one file per card
  components/ui/*             Chakra snippets (provider, color-mode, clipboard, field)
```

Every user action goes through `runAction`. Cards never write to the ledger directly.

## 3. Runtime configuration contract

Rendered by `docker/entrypoint.sh` into `/config.js` (`Cache-Control: no-store`), read synchronously
by `src/config.ts`, validated with zod. The same names drive `pnpm dev` from `.env`.

| Variable | Required | Shape |
|---|---|---|
| `GIANO_WALLET_URL` | yes | URL; only its origin is used |
| `GIANO_CHAINS` | yes | JSON array of `{ chainId: int, name, rpcUrl: http(s) URL or "/rpc/<chainId>", explorerUrl?, defaultToken?: address }` |
| `GIANO_RPC_UPSTREAM_<chainId>` | no | keyed upstream for the same-origin proxy of that chain |
| `GIANO_OTHER_WALLET_URL` | no | a wallet origin that does not allow-list this dApp |
| `GIANO_APP_LABEL` | no | free text |
| `GIANO_CSP_CONNECT_SRC` | no | override of the composed `connect-src` |

Deprecated for one release, converted with a log line, refused when `GIANO_CHAINS` is also set:
`GIANO_CHAIN_ID`, `GIANO_CHAIN_NAME`, `GIANO_RPC_URL`, `GIANO_CHAIN_B_ID`, `GIANO_CHAIN_B_NAME`,
`GIANO_RPC_B_URL`, `GIANO_TEST_ERC20`, `GIANO_RPC_UPSTREAM` (maps to the first chain). Removal is
the release after the one that ships this document.

Validation splits: the entrypoint checks presence, mutual exclusivity and that `GIANO_CHAINS` is an
array; the browser validates every field and renders a configuration-error screen naming the invalid
paths, constructing no provider.

Response headers on every route: `X-Frame-Options: DENY`, a CSP whose `connect-src` is `'self'`, every
RPC origin and both wallet origins, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
**no** `Cross-Origin-Opener-Policy`. `/config.js` is `no-store`; HTML is `expires epoch`; hashed
assets are immutable. nginx's `add_header`-in-location replacement rule means each location restates
the security headers.

## 4. The ledger

```ts
type LedgerEntry = {
  id; at; section; label; method; params?; chainId; chainName; walletOrigin; account?;
  declaredPayer?: 'sponsored' | 'self-paid';
  status: 'pending' | 'submitted' | 'ok' | 'confirmed' | 'failed' | 'refused' | 'timed-out' | 'violation';
  expected?: boolean;            // a deliberate failure control
  result?; userOpHash?; txHash?; receipt?: UserOpReceipt;
  attribution?: { actualPayer; paymaster?; actualGasCost?; nativeDelta?; matchesDeclared?; note };
  balances?: { nativeBefore?; nativeAfter?; tokenBefore?; tokenAfter?; token? };
  error?: { name; code?; message; data?; reason?; requestedChainId?; supportedChainIds?; meaning?; action? };
  note?; durationMs?;
};
```

Persisted under `giano-demo:ledger:<walletOrigin>`; capped at 500 — the oldest entries are evicted beyond the cap, the
eviction count is shown, and exports contain retained entries only (the one removal path besides Clear);
entries still pending at unload are marked `timed-out`. Export = entries + events + runtime config +
connector version + user agent + dApp origin. Provider events (`connect`, `accountsChanged`,
`chainChanged`, `disconnect`) are a parallel list.

## 5. Setup preflight

| Check | How | Fail → |
|---|---|---|
| Wallet origin reachable | `GET ${walletUrl}${walletApiPath}/v1/version` | unreachable, or this origin not in `corsOrigins` (CORS), or CSP omits the wallet origin; receipts at risk → transactions card warns |
| Own COOP header | `fetch(location.href)` and read `Cross-Origin-Opener-Policy` | `same-origin` → handshake will time out |
| RPC chain id, per chain | `eth_chainId` vs configured | wrong network → that chain's write controls disabled |
| Default token, per chain | `eth_getCode(defaultToken)` | `0x` → warn; ERC-20 card opens empty |
| Browser storage | write/read probe | warn: no session resume, no ledger persistence |
| Version skew | connector version (from the installed manifest at build time) vs wallet-api version | SDK ahead of api → warn with the upgrade order |

Not checkable from the dApp: `allowedDappOrigins` (undisclosed by design; the failure lab provokes
it) and the tenant's sponsorship configuration (a refusal shows only in the wallet, G5).

## 6. Section-by-section UI

1. **Header** — brand mark, "Giano Demo", `appLabel` badge, wallet origin, connector version;
   connected status (dot + text), address with copy, Connect on `<chain>` / Disconnect, colour mode.
   Reconnect prompt (Alert) on 4900; violation banners (persistent, copy report, dismiss).
2. **Preflight line** — one line: "Setup verified · n checks · t" or "n setup problems · titles";
   link to the card.
3. **Jump bar** — anchors to every card.
4. **Preflight card** — table of checks (state, title, observed detail, action); Re-run.
5. **Chain** — segmented control of chains (configured + ad-hoc; wrong-network ones disabled);
   "Add a chain…" disclosure (chain id, RPC URL); served-by-wallet status, balance, account
   deployment, granted chain; Connect, Read `eth_chainId`, Try `switchEthereumChain`, Try
   `addEthereumChain`; provider options disclosure (`walletApiPath`, storage, `sdkVersion`, Apply to
   next provider); outcomes.
6. **Identity** — table chain → granted address → status (reference / identical / differs / Connect);
   "Invariant held" line when ≥2 chains agree.
7. **Transactions** — action picker (0 ETH to self, value to address, unlisted contract, custom);
   gas payer segmented control; To / Value / Calldata; Send; balance + Fund from devnet (probes
   `anvil_setBalance`, hides when refused, faucet hint otherwise); receipts-at-risk warning; keep
   waiting after a timeout; outcomes.
8. **Signing** — message; method picker (`personal_sign`, `eth_sign`, `eth_signTypedData_v4`); Sign;
   typed-data disclosure (editable, reset); outcomes.
9. **Raw user operation** — stepper Prepare → Sign → Send signed and wait, each payload in a code
   block; `signed_eth_call` on `privateBalanceOf`, plus the no-`to`/`data` validation control.
10. **ERC-20** — token address (default per chain), Load, Refresh; metadata, balance, allowance;
    destination/spender, amount; action picker (Mint, Transfer, Approve, Sign permit) + gas payer;
    Run; outcomes with token deltas.
11. **Wallet management** — Manage wallet; "closed, returned undefined" or violation.
12. **Adapters** — wagmi status, Connect via wagmi, `switchChain` → other chain (refusal expected),
    Send + `waitForUserOperationReceipt`; RainbowKit connect modal listing Giano. Lazy-loaded.
13. **Failure lab** — grid of controls: popup blocked (1.5 s delayed call), unserved chain 99999,
    disallowed origin (foreign provider against `otherWalletUrl`), user rejection, revoke then
    `eth_accounts`, invalid address, invalid calldata; outcomes.
14. **Ledger** — filter (All / Failed / Refused / Violations), table with expandable rows, Export
    JSON (clipboard), Clear; eviction notice.
15. **Events** — provider events, newest first.

Outcome rows: status (dot + text, spinner while pending), label, summary (chain · payer ·
as-declared/mismatch · short hash · duration), chevron; details = key/value list of the whole entry
+ "Copy entry as JSON". Latest row open, others folded.

## 7. Guards: lint and bundle scan

`eslint.config.js` (ESLint 9 flat config, typescript-eslint, eslint-plugin-react):
`no-restricted-imports` bans `@appliedblockchain/*` except the connector's default entry, relative
paths leaving `src/`, and `*.css` except `@rainbow-me/rainbowkit/styles.css`;
`react/forbid-dom-props` bans `style`; `react/forbid-component-props` bans `style` and `css`.
`scripts/scan-bundle.mjs` fails the build on `navigator.credentials`, any `VITE_` token, or a
stylesheet in `dist/` that is not RainbowKit's (recognised by content). `pnpm build` = lint →
typecheck → vite build → scan.

## 8. Local origins and e2e

`e2e/origins.mjs` gains `demo` (4410) and `demo-byo` (4411). `deploy/docker-compose.e2e.yml` adds
`http://demo.localhost` / `http://demo-byo.localhost` to both tenants' `allowedDappOrigins` and
`corsOrigins` and to wallet-web's `GIANO_ALLOWED_DAPP_ORIGINS`. The fixture's `app` / `app-byo`
origins and the existing seven Playwright specs are unchanged. `pnpm demo:stock` / `demo:byo`
start the demo on the new ports. An opt-in Playwright project (`--project demo`) smoke-tests the
demo (R18 assumption).

## 9. Deployment

- `deploy/docker-compose.infrastructure.yml`: both demo services on `GIANO_CHAINS` with the devnet
  test token as `defaultToken`; wallet-web serves chain B with `sponsorship: off` so the self-paid
  path is reachable (D5); `GIANO_OTHER_WALLET_URL` points each demo at the other tenant.
- `deploy/docker-compose.infrastructure.aws.yml` and `infra/iac/ecs_services.tf`: `GIANO_CHAINS`
  (Base Sepolia + Ethereum Sepolia, `rpcUrl: /rpc/<chainId>`), keyed upstreams as
  `GIANO_RPC_UPSTREAM_<chainId>` secrets, `GIANO_OTHER_WALLET_URL` when the BYO tenant exists.
  `defaultToken` joins once the test ERC-20 is deployed to both testnets (`local.example_dapp_chains`).
- Rollout: images build as before (`giano-example`); the scalar variables keep working during the
  transition; rollback = revert `infra/versions.json`.

## 10. Traceability

| Requirement | Where |
|---|---|
| R1 | `services/custom-example/**` |
| R2 | D2; `eslint.config.js`; `scripts/scan-bundle.mjs` |
| R3 | D13; `DEVELOPER-GUIDE.md` §3–4; `INTEGRATION.md` §9 |
| R4, R5 | D10; `src/theme.ts`; lint |
| R6 | §6 cards 5–13; `README.md` table |
| R7 | Failure lab; error records (`lib/errors.ts`); preflight |
| R9 | §4 ledger; `OutcomeRow`; Export |
| R10 | Chain card; `ChainRegistry` |
| R11 | Identity card; violations |
| R12 | D5; Transactions and ERC-20 payer controls; infrastructure compose chain B |
| R13, R14 | ERC-20 card; D12; `test-erc20-registry` spec |
| R15 | Wallet management card |
| R16, R17 | §3; `docker/`; scan |
| R18 | §8; Playwright `demo` project |
| G1–G6 | `DEMO-REQUIREMENTS.md` §5; annotations in `lib/errors.ts` |
