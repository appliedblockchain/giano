## Why

`services/custom-example` is the only rich, deployed Giano dApp, yet it flatters Giano rather than testing it: it hides
failures behind toasts, exposes a fraction of the SDK surface, hard-wires two chains, has no unsponsored path, and imports
workspace internals a real client cannot. Giano now ships published packages, a multi-chain wallet-api, a production
paymaster and wallet management; the demo must become the reference integration that exercises all of it as an ordinary
client would, so that integration defects show up here first, not at a tenant.

## What Changes

- **Rebuild `services/custom-example`** as a Vite + React + Chakra UI dApp built only on the published Giano surface
  (`@appliedblockchain/giano-connector` public entry point, `viem`, optionally `wagmi`). No imports of `giano-contracts`,
  `giano-wallet-*` or any workspace path; enforced by lint.
- **Every SDK method reachable from the UI**: connect, session resume, `eth_sendTransaction`, `personal_sign`, `eth_sign`,
  `eth_signTypedData_v4`, the three raw user-operation methods, `signed_eth_call`, `waitForUserOperationReceipt`,
  `openWalletManagement`, `wallet_switchEthereumChain` / `wallet_addEthereumChain` (expected refusal),
  `wallet_revokePermissions`, `disconnect`, `isConnected`, `chainId`, `supportedChainIds`, provider events and
  options (`walletApiPath`, `storage`), plus the wagmi connector (`createGianoConnector`, `switchChain` refusal,
  `waitForUserOperationReceipt`) and the RainbowKit adapter (`giano()`).
- **Setup preflight at load**: wallet origin reachability and CORS, own COOP header, RPC chain id per chain, default
  token code, storage availability, SDK versus wallet-api version, each with pass/warn/fail and the operator action.
- **Failure paths are first-class controls**: user rejection, popup blocked (call outside a user gesture), unserved chain
  (4902), unavailable chain (4901), disallowed origin (`origin-not-allowed`), insufficient balance for a self-paid operation, sponsorship refusals by reason,
  non-EIP-2612 token, malformed inputs.
- **Persistent, attributable outcome ledger**: every action appends an entry with method, params, chain, tenant wallet
  origin, userOp hash, transaction hash, full receipt (sender, paymaster, gas cost), native and token balance deltas and
  the complete error object. Entries persist across reloads and export as JSON. Toasts are removed as the record of truth.
- **Chain selection in the UI** from a runtime-configured list of N chains, plus a free-form chain id to provoke
  refusals. **Address identity across chains is asserted**, not assumed: the demo compares the account each chain's
  provider grants and renders a mismatch as a violation.
- **Sponsored and self-paid gas both reachable**: the user declares the expected payer per transaction; the demo
  attributes the actual payer from the receipt and flags disagreement. Native balance and a funding affordance make the
  self-paid and insufficient-balance paths exercisable.
- **ERC-20 section** with a per-chain default token, read, mint (anyone can mint Giano's test ERC-20), transfer, approve,
  allowance, EIP-2612 permit signature; default token at the same CREATE2 address on every supported chain.
- **Wallet management** opened through the SDK only, with the "no data returned" invariant asserted.
- **Build once, deploy anywhere**: one image; configuration injected at container start as `/config.js` following the
  Baanx pattern (placeholders substituted at start, then exec nginx); `GIANO_CHAINS` JSON supersedes the two-chain scalar
  pair (scalar pair still accepted); validated in the browser with a visible configuration-error screen; no secrets in the
  bundle, keyed RPC URLs only via the same-origin proxy.
- **Applied Blockchain branding** via a single Chakra theme token file; no custom CSS anywhere (lint-enforced).
- **Docs converge on the demo** (`specs/DEVELOPER-GUIDE.md` §4, `specs/INTEGRATION.md` §9): snippets are lifted from the
  demo source; a new `specs/DEMO-REQUIREMENTS.md` and `specs/DEMO-SPECS.md` record the requirements and decisions in the
  repository's established form.
- **Deploy the test ERC-20 to each testnet with CREATE2** and record the address in the contracts registry.
- **e2e untouched in behaviour, improved in ergonomics**: the demo moves to its own portless names so it can no longer be
  mistaken for the fixture; an opt-in Playwright project smoke-tests the demo.
- **BREAKING (env contract of the `giano-example` image)**: `GIANO_CHAINS` becomes the primary chain configuration;
  `GIANO_TEST_ERC20` moves inside each chain entry. The scalar variables keep working for one release with a deprecation
  log line.

## Capabilities

### New Capabilities
- `demo-dapp`: behaviour of the reference dApp — session, chain selection and identity assertion, actions per SDK
  method, gas payer declaration and attribution, ERC-20 operations, wallet management entry, failure-path controls, the
  outcome ledger, branding and styling constraints.
- `demo-deployment`: the `giano-example` container contract — runtime configuration injection, validation, one image for
  both tenant shapes, security headers, no secrets in the bundle, published-surface-only dependency rule.
- `test-erc20-registry`: Giano's test ERC-20 deployed deterministically to every supported testnet at one address and
  published through the contracts registry.

### Modified Capabilities
- none (`openspec/specs/` is empty; the demo's documentation contract with `DEVELOPER-GUIDE.md` and `INTEGRATION.md` is
  captured under `demo-dapp`).

## Impact

- **Code**: `services/custom-example/**` rewritten (keeping Dockerfile/nginx/entrypoint shape, `window.__GIANO_CONFIG__`
  mechanism, panel decomposition); `packages/contracts/addresses.ts` + `ignition/deployments/chain-<id>` gain the test
  ERC-20; `e2e/origins.mjs`, `deploy/docker-compose.e2e.yml`, `deploy/docker-compose.infrastructure*.yml`,
  `infra/iac/ecs_services.tf` updated for the new env contract and demo origins; `specs/DEVELOPER-GUIDE.md`,
  `specs/INTEGRATION.md`, new `specs/DEMO-REQUIREMENTS.md`, `specs/DEMO-SPECS.md`.
- **Dependencies**: `@appliedblockchain/giano-connector` (workspace today, GitHub Packages once H2 lands — same import
  path), `viem`, `wagmi` + `@tanstack/react-query`, `@chakra-ui/react` v3 (with its MCP server for GenAI tooling),
  `react-icons`, `zod` (config validation). `@appliedblockchain/giano-contracts` dependency removed.
- **Giano findings surfaced by this design** (tracked in design.md, not fixed here): no dApp-side way to request a
  self-paid operation when a wallet origin sponsors; the read-only RPC relay is wallet-origin-bound so a dApp still needs
  its own RPC endpoint; the demo/fixture port clash; a sponsorship refusal reaching the dApp as a bare 4001.
- **Estimate**: the ticket is sized at 3 SP. tasks.md separates the core (what 3 SP buys) from stretch groups so the
  scope decision is explicit rather than silent.
