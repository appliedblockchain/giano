## Context

See proposal.md for motivation. What shapes the approach:

- **Existing demo is ~80% of the shape.** `services/custom-example` already has Vite + React 19 + Chakra UI v3, a
  `window.__GIANO_CONFIG__` runtime-config mechanism rendered by `docker/entrypoint.sh` with `envsubst`, an nginx image
  with CSP and a same-origin `/rpc` proxy, and four panels (wallet, cross-chain, ERC-20, sponsorship). It also has
  toasts as the record of outcomes, a hard-wired two-chain model, a `giano-contracts` dependency it does not need, a
  gradient `globalCss` background and frosted-glass card styling, and no unsponsored path.
- **The public SDK surface** (`packages/connector/src/index.ts`): `createGianoWalletProvider` → `GianoWalletProvider`
  with `request`, `on`, `removeListener`, `isConnected`, `disconnect`, `openWalletManagement`, `chainId`,
  `supportedChainIds`; `createGianoConnector` (wagmi) with `UnsupportedChainSwitchError`; `giano` (RainbowKit); error
  classes `TransportError` (codes `POPUP_BLOCKED`, `POPUP_CLOSED`, `HANDSHAKE_*`, `REQUEST_TIMEOUT`, `DISCONNECTED`,
  `NOT_CONNECTED`), `TransportRpcError`, `HandshakeRefusedError`, `UnsupportedChainError` (4902), `RPC_ERRORS`. Wallet
  methods routed to the popup: `eth_requestAccounts`, `eth_sendTransaction`, `personal_sign`, `eth_sign`,
  `eth_signTypedData_v4`, `eth_prepareUserOperation`, `eth_signUserOperation`, `eth_sendSignedUserOperation`,
  `signed_eth_call`, `giano_openWalletManagement`. Local: `eth_accounts`, `eth_chainId`, `waitForUserOperationReceipt`
  (polls `${walletOrigin}/api/v1/userops/<hash>/receipt`), `wallet_revokePermissions`; `wallet_switchEthereumChain`
  and `wallet_addEthereumChain` throw 4200; everything else goes to the read transport.
- **Gas payment is a wallet-origin setting, not a request option.** wallet-kit resolves `sponsorship` per chain as
  `service | test-paymaster | off`. With `service`, the review screen refuses before approval when the rules engine
  says no, and offers only Close: there is no "pay it myself" fallback. Only `off` produces the genuinely unsponsored
  path (`not-applicable`, user pays from the account's native balance).
- **The read-only RPC relay** (`POST /v1/rpc/:chainId`) resolves the tenant from the `Origin` header via
  `walletOrigin`/`expectedOrigins`, i.e. wallet origins. A dApp origin is a `corsOrigin`, not an expected origin, so
  the demo cannot use it and still needs its own RPC endpoint per chain.
- **Baanx runtime-injection pattern** (`services/admin/entrypoint.c`, `Dockerfile`, `nginx.conf` in
  `appliedblockchain/baanx`): the built `index.html` carries `${VAR}` placeholders; a shell-free static entrypoint
  substitutes them from the environment at container start, writes the file back and `execv`s nginx; HTML is served
  with `expires epoch`, assets with long max-age. Same principle as Giano's current entrypoint, with a separate
  rendered file instead of rewriting `index.html`.
- **e2e** drives `e2e/dapp` on ports 4400/4401 under `app.localhost`/`app-byo.localhost`, the only dApp origins the e2e
  tenants allow-list; `reuseExistingServer: true` means a running demo on those ports silently breaks the suite.
- **Test ERC-20** (`PrivateERC20`, public `mint(uint256)`, `privateBalanceOf`, EIP-712 `approveMessage`) is deployed
  via Ignition `Testing` module with `--strategy create2` and salt `0xAB…AB`; present in devnet state at
  `0x9967bDf9…74D8`, absent from `chain-84532` and `chain-8453` journals. `addresses.ts` already has an optional
  `testErc20` field.
- **Constraints from the ticket**: published packages only (R2, refactor to registry install after H2), no custom CSS
  (R4), AB branding (R5), no secrets (R17), build once / deploy anywhere (R16), do not break Playwright.

## Goals / Non-Goals

**Goals:**
- One dApp that an integrator can copy file-for-file, and that a Giano engineer can use to reproduce a defect from a
  screenshot or an exported ledger.
- Cleaner code over design fidelity: Chakra components and theme tokens, nothing bespoke.
- Zero coupling to workspace internals, enforced mechanically.

**Non-Goals:**
- Changing Giano core (connector, wallet-kit, wallet-web, wallet-api). Gaps found are written up as findings (below) and
  handed on; the demo shows them, it does not paper over them.
- Building a BYO wallet UI, a balances/history product, or tenant onboarding.
- Matching Claude Design output pixel-for-pixel.
- A server-side component in the demo image (see D6).

## Decisions

### D1 — Stack: Vite + React 19 + TypeScript + Chakra UI v3, `viem` pinned, `wagmi` for the connector section
Keep what exists; it satisfies R4/R5 through theme tokens and Chakra has first-class GenAI tooling (`@chakra-ui/react-mcp`
MCP server and LLM docs). `wagmi` + `@tanstack/react-query` are added because `createGianoConnector` is part of the
published surface and R6 says every method is reachable. RainbowKit (`giano()`) is a one-line adapter with a heavy
dependency tree; it is a stretch task, not core.
*Alternatives*: MUI (no MCP, heavier theming), shadcn/Tailwind (utility classes are CSS authoring, conflicts with R4).

### D2 — Published surface only, enforced by ESLint `no-restricted-imports`
Only `@appliedblockchain/giano-connector` is allowed among `@appliedblockchain/*`; relative imports may not leave
`services/custom-example/src`. The dependency is `workspace:^` until H2 publishes; the Dockerfile builds the workspace
packages today and collapses to a plain `pnpm install` from GitHub Packages afterwards. The import path is identical in
both states, so R2 costs one `package.json` line later.
*Alternative*: install from the registry now — blocked on H2.

### D3 — One provider per chain, built lazily from the runtime chain list; chain selection = provider selection
This is Giano's real mechanism (MC-01/MC-10) and what the current cross-chain panel already does. A `ChainRegistry`
holds `{ chain, provider, publicClient }` per configured chain plus any ad-hoc chain the user adds (free-form chain id +
RPC URL), which is how the unserved-chain (4902) and unavailable-chain (4901) paths are provoked from the UI.
`wallet_switchEthereumChain` is exposed as a deliberate control whose success would be a violation.

### D4 — Address identity is asserted from granted accounts, not computed
The dApp has no owner bytes and no factory access through the public surface, so the only client-observable proof of
R11 is that each chain's `eth_requestAccounts` returns the same address. The demo keeps `Map<chainId, address>` and
renders a persistent violation banner on disagreement. `supportedChainIds` advertised by the wallet is compared with the
configured list, and chains configured but not served are shown as such.

### D5 — Gas payer: declared by the user, attributed from the receipt
Because the dApp cannot request self-payment (see finding G1), the demo asks the user what they *expect* (sponsored /
self-paid) and attributes what *happened*: `receipt.paymaster` non-zero ⇒ sponsored; native balance delta ≈
`actualGasCost` ⇒ self-paid. Disagreement is a flagged entry. To make the self-paid path reachable in the reference
stacks, `deploy/docker-compose.infrastructure.yml` configures wallet-web with chain B (`31338`) as `sponsorship: off`
while chain A stays `service`. The e2e stack is untouched. The demo shows the account's native balance and a "fund from
devnet" control that probes `anvil_setBalance` once per chain and hides itself when the node refuses, so the
insufficient-balance path is a two-click reproduction on devnet and a documented faucet step on a testnet.
*Alternative*: invent a per-request opt-out param — would be a Giano change disguised as demo code.

### D6 — Configuration: `GIANO_CHAINS` JSON rendered to `/config.js` at start; no secrets; no Node in the image
Aligns the demo's env contract with wallet-api/wallet-web (`GIANO_CHAINS`) and removes the two-chain ceiling. The
rendering stays a shell entrypoint with `envsubst` on an explicit variable allowlist. The nginx image has neither
`node` nor `jq`, so validation splits: the entrypoint checks presence, mutual exclusivity of `GIANO_CHAINS` versus the
scalar pair, and that `GIANO_CHAINS` starts with `[`; the browser validates the full JSON shape with `zod` and renders a
configuration-error screen on failure. Keyed RPC URLs are handled as today: `rpcUrl:
"/rpc/<chainId>"` plus `GIANO_RPC_UPSTREAM_<chainId>` for the nginx `proxy_pass`, never rendered to `/config.js` or the
CSP. Baanx's shell-free C entrypoint is noted, not adopted: its value is a hardened base image the Giano images do not
use; the substitution principle is the same.
**`@appliedblockchain/secret-manager-client` is not used in v1.** It is a Node library for reading cloud secrets into a
process; the demo image has no Node process and, by R17, no secret to read. Adopting it would mean replacing nginx with
a Node edge server that resolves `aws-sm://` references for the RPC upstream. That is a legitimate follow-up if the
team wants keyed RPC secrets pulled by the container rather than injected by ECS, and it is listed under Open Questions
for a decision rather than built by default.

### D7 — Outcome ledger as the single record; toasts removed
A `LedgerEntry` type (timestamp, section, method, params, chainId/chainName, walletOrigin, declaredPayer, status,
userOpHash, txHash, receipt, balancesBefore/After (native + token), error {name, code, message, data}, durationMs)
stored in a reducer and mirrored to `localStorage` under a wallet-origin-namespaced key. Rendered as a Chakra `Table`
with expandable rows (`Collapsible`) and per-row `Clipboard`; an Export control copies the full ledger plus runtime
config and connector version as JSON. `console.info/error` mirrors remain. Chakra's `Toaster` is dropped.

### D8 — Information architecture (the UI half)
Single page, `Container maxW="5xl"`, a sticky header and a vertical stack of sections. Every section is a Chakra
`Card` with a title, one-line purpose, controls on the left, and a compact "last outcome" on the right that links to the
ledger row. Sections, top to bottom:

1. **Header** — brand mark and name (theme tokens), `appLabel` badge (tenant), wallet origin, connector version,
   theme toggle. Connect/Disconnect, account address with copy, `isConnected()` badge.
2. **Preflight** — runs at load and on demand; one row per check (wallet origin reachable + CORS,
   own COOP header, RPC `eth_chainId` per chain, default token code per chain, storage available, connector vs
   wallet-api version) with pass/warn/fail and the operator action; collapses to one line when all pass (D14).
3. **Chain** — `SegmentedControl` (or `RadioCard`) of configured chains; each card shows chain id, name, served-by-wallet
   badge (from `supportedChainIds`), native balance, account deployed-on-chain badge. Free-form "Add chain" fields
   (chain id, RPC URL) for provoking 4902/4901. Provider options disclosure per chain (`walletApiPath`, storage
   backend). Controls: Connect on this chain, Read `eth_chainId`, Attempt `wallet_switchEthereumChain`, Attempt
   `wallet_addEthereumChain`.
4. **Identity** — table of chain → granted address, status "identical" / violation banner (persistent `Alert`).
5. **Transactions** — declared payer `RadioGroup` (sponsored / self-paid); presets: Send 0 ETH to self, Send value to
   address, Call unlisted contract (refusal), Arbitrary target + calldata; Fund from devnet; result panel with hash →
   receipt → balances.
6. **Signing** — message input; `personal_sign`, `eth_sign`, `eth_signTypedData_v4` (editable typed-data JSON).
7. **Raw user operation** — three-step stepper: prepare (calls JSON) → sign → send; each step's payload shown in a
   `Code` block; then wait for receipt. Plus `signed_eth_call` against the default token's `privateBalanceOf`.
8. **ERC-20** — token address (prefilled from selected chain's `defaultToken`), Load, metadata badges, balance,
   allowance; Mint (amount), Transfer, Approve, Sign permit; destination defaults to own account.
9. **Wallet management** — one button, `openWalletManagement()`, outcome "closed, no data" or error.
10. **wagmi** — `WagmiProvider` scoped to this card; connect via `createGianoConnector`, `useAccount`, `switchChain` to
   another configured chain (expected `UnsupportedChainSwitchError`), send + `waitForUserOperationReceipt`.
11. **Failure lab** — buttons: Reject in wallet (instructions), Popup blocked (delayed call, 1.5 s after click),
    Unserved chain (id 99999), Disallowed origin (provider against the other tenant's wallet origin →
    `origin-not-allowed`), Invalid address, Invalid hex, Revoke permissions then `eth_accounts`.
12. **Ledger** — table, filters by section/status, Export JSON, Clear.
13. **Events** — live provider event log (`connect`, `accountsChanged`, `chainChanged`, `disconnect`).

UX rules that hold on every card, decided 2026-09-16 after a review of three alternative directions (the stock Chakra
look was kept; the rules below are what changed): status is a dot plus text, never a stack of badges; each card has one
action picker (`Select`) and one primary button instead of a grid of buttons; every outcome is a ledger-style row with a
one-line summary (status, label, payer, short hash, duration) and details folded behind it, only the latest open;
secondary controls (`eth_chainId`, switch/add attempts, fund from devnet) are ghost buttons; provider options sit in a
closed `Collapsible`; a jump bar of section anchors runs under the header; the preflight verdict is one line under the
header that expands to the full card. Loading states use Chakra `Button loading`; every async control disables its
section's other write controls while pending. No modals: outcomes render in place. Recovery affordances live on the entry that needs them: a `disconnect`
with 4900 raises a reconnect prompt in the header; a receipt timeout keeps the hash and offers "keep waiting"; a 4001
after a sponsored send is annotated "closed by the user or refused in the wallet" because the dApp cannot tell (G5). Mobile: sections stack; tables get `overflowX="auto"`.

### D9 — Brief for Claude Design (input to the Applied Edge Design System)
"Design a single-page developer demo for a passkey smart-wallet SDK using the Applied Edge Design System. Twelve stacked
cards as listed above; dense, engineer-facing, monospace for hashes and addresses; persistent success/error rows rather
than toasts; a red persistent banner for invariant violations. Use only components that map one-to-one to Chakra UI v3
primitives (Card, Table, Badge, Alert, Button, Input, RadioGroup, SegmentedControl, Collapsible, Code, Clipboard,
Tabs). No custom CSS, gradients or illustrations. Light and dark mode via tokens. Cleaner code beats design fidelity:
the build may simplify layouts freely." The output (screens + token export: brand colours, font stack, radius) goes into
`specs/DEMO-SPECS.md` §UI and `src/theme.ts`. Until tokens arrive, `theme.ts` carries neutral placeholders in the same
token names so nothing else changes.

### D10 — Branding seam and CSS ban
`src/theme.ts` (`createSystem(defaultConfig, defineConfig({ theme: { tokens, semanticTokens } }))`) is the only place
brand appears; `colorPalette="brand"` everywhere else. Lint: `no-restricted-imports` for `*.css`, `react/forbid-dom-props`
for `style`, `react/forbid-component-props` for `css` and `style`; `globalCss` absent by review. Fonts: system stack
unless the design system provides a self-hosted font (no Google Fonts link — removes two CSP origins).

### D11 — Demo gets its own origins; e2e fixture untouched
`e2e/origins.mjs` gains `demo` (4410, `demo.localhost`) and `demo-byo` (4411, `demo-byo.localhost`); the e2e compose
seeds both tenants with these as additional `allowedDappOrigins`/`corsOrigins` and wallet-web's
`GIANO_ALLOWED_DAPP_ORIGINS`. `pnpm demo:*` scripts move to those ports. Playwright's default project is unchanged; a
new opt-in `demo` project (`--project demo`) runs a smoke spec against the demo (connect, send, ledger row present).
This removes the documented port-clash gotcha instead of documenting it harder.

### D12 — Test ERC-20 on testnets
Run `hh:deploy:testing --network base-sepolia|sepolia` with `PAYMASTER_FUND_ETH` small (the module also deploys the
permissive paymaster; acceptable on a testnet, and the address of the ERC-20 does not depend on it). Verify the address
equals the devnet one (same bytecode, constructor arg, salt, deterministic deployer); if the compiler output differs, the
new address is recorded and the devnet state regenerated so all chains agree. `addresses.ts` publishes `testErc20` for
84532 and 11155111; `address-overrides.json` keeps it out of 8453.

### D13 — Documentation convergence
`specs/DEVELOPER-GUIDE.md` §4.2–4.5 and `specs/INTEGRATION.md` §9 snippets are rewritten to match demo code, and the
demo files are referenced by path. New `specs/DEMO-REQUIREMENTS.md` (R1–R17 as stated, with the two missing numbers
noted, plus the Giano findings) and `specs/DEMO-SPECS.md` (this design's decisions, config contract, UI spec, traceability
R → section) follow the form of `PAYMASTER-REQUIREMENTS.md` / `PAYMASTER-SPECS.md`, at a fraction of the length.

### D14 — Setup preflight: detect misconfiguration at load, never block on it
Most deployment mistakes surface today as a 15 s handshake timeout or a 120 s receipt timeout. Six checks answer them
in under a second from the browser: `GET ${walletUrl}/api/v1/version` (reachability and, because it is cross-origin,
whether this dApp origin is in the tenant's `corsOrigins`; also yields the wallet-api version for the skew check);
`fetch(location.href)` and read the `Cross-Origin-Opener-Policy` header; `eth_chainId` on each chain's RPC compared
with the configured id (a silent wrong-network read path is the worst failure on the list); `eth_getCode` on each
default token; a `localStorage` write/read probe; connector version from `package.json` versus wallet-api version.
Results render as a card at the top with the operator action per row; a failed row disables the write controls it
invalidates (wrong-network chain) or attaches a warning to them (CORS → receipts). It is re-runnable and never blocks
the page, so a check that is itself wrong cannot hide the demo. Not checkable from the dApp: the tenant's
`allowedDappOrigins` (undisclosed by design; the failure lab provokes it instead) and sponsorship configuration (G5).

## Giano findings surfaced by this design (not fixed here)
- **G1 — No client-side way to request an unsponsored operation.** With `sponsorship: service`, a refusal ends in Close;
  a user with native balance cannot pay. Suggest: a review-screen fallback ("pay the fee from this wallet") and/or an
  EIP-5792-style capability the dApp can send. The demo surfaces this through D5.
- **G2 — dApps have no key-free read path.** The RPC relay is wallet-origin-bound; a dApp on a testnet must ship its own
  RPC URL (public or keyed-behind-proxy). Suggest: accept `corsOrigins` on `/v1/rpc/:chainId`.
- **G3 — Receipt polling endpoint is the only cross-origin fetch a dApp makes**, and it is easy to omit from CSP; the
  connector could surface a clearer error than a 120 s timeout when the fetch is blocked.
- **G5 — A sponsorship refusal is indistinguishable from a user rejection at the dApp.** Both arrive as 4001 when the
  popup closes; the reason lives only in the wallet console (paymaster decision S8). Suggest a typed `data.reason` on
  the 4001 when the wallet refused before approval, so integrators can show "not sponsored" instead of "you cancelled".
- **G6 — The dApp origin allow-list is not discoverable before connecting**, so the most common deployment mistake is
  diagnosable only after a popup. The nack reason `origin-not-allowed` is good; a public well-known document listing
  allowed dApp origins per tenant would let a preflight catch it.
- **G7 — `createGianoConnector.connect()` ignores wagmi's `isReconnecting`.** wagmi's default `reconnectOnMount` calls
  `isAuthorized()` (true once the raw provider has a cached session) then `connect()`, which always issues
  `eth_requestAccounts`; a second Connect popup opens and blocks every later request. Found by the demo on
  2026-09-16; the demo sets `reconnectOnMount={false}`. Fix: on `isReconnecting`, answer from `eth_accounts`.
- **G8 — wallet-web's HTML shell is cacheable.** No `Cache-Control: no-cache` on `/`, so a redeploy leaves a warm
  browser on the previous bundle until a hard reload (seen 2026-09-16 as a stale "wallet misconfigured" popup). Fix:
  `expires epoch` on the shell, as the demo image does.
- **G4 — `waitForUserOperationReceipt` returns an untyped `unknown`**; the demo must cast. A published `UserOperationReceipt`
  type on the provider would remove a class of integration bugs.

## Risks / Trade-offs
- [Self-paid path depends on a wallet-origin config in the reference stack] → documented in `DEMO-SPECS.md`; the demo
  states on screen which chain is expected to be unsponsored and flags disagreement, so a misconfiguration is visible.
- [Ledger in `localStorage` can grow] → cap at 500 entries with oldest-first eviction, warn in UI before evicting.
- [Chakra v3 API churn vs. MCP docs] → pin `@chakra-ui/react` minor; run the MCP server for component lookup during build.
- [wagmi adds bundle weight to a "thin" demo] → isolated in its own card and lazy-loaded (`React.lazy`), so the bundle
  scan for `navigator.credentials` and the thin-SDK claim remain true.
- [Env contract change breaks running deployments] → scalar variables accepted for one release; compose and Terraform
  updated in the same change.
- [Test ERC-20 CREATE2 address may differ from devnet if bytecode changed] → verify before recording; regenerate devnet
  state if needed (determinism CI gate).
- [Brand tokens not yet available] → neutral placeholders under the final token names; swapping is one file.
- [3 SP is below the full list] → tasks.md marks core vs stretch; the preflight card, the missing controls and the
  RainbowKit adapter were promoted to core on 2026-09-15 at the user's request.

## Migration Plan
1. Land the rebuild with the dual env contract; images build in `docker.yml` as before (`giano-example`).
2. Update `deploy/docker-compose.infrastructure*.yml` and `infra/iac/ecs_services.tf` to `GIANO_CHAINS`.
3. Deploy the test ERC-20 to Base Sepolia and Ethereum Sepolia; publish `addresses.ts`; set `defaultToken` in dev env.
4. Roll dev via `infra/versions.json`. Rollback = revert the SHA; the previous image ignores `GIANO_CHAINS` and still
   reads the scalars, which remain set during the transition.
5. Remove scalar support in the following release.

## Open Questions
- Does the team want the demo image to pull RPC secrets itself (Node edge server + `secret-manager-client`) rather than
  receive them from ECS task secrets? Decision changes D6 and adds a server task group; safe to defer since the browser
  contract (`/rpc/<chainId>`) is identical either way.
- R8 and R18 are referenced by the ticket but not defined. R18 is assumed to mean "automated coverage of the demo"
  (D11's opt-in Playwright project). Confirm or correct before the stretch group is started.
