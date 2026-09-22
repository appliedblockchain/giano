# Giano reference dApp — requirements

Giano ships as published packages, a multi-tenant wallet-api, a production paymaster and wallet
management. The one place all of that meets an integrator is a dApp — and until now the only rich,
deployed dApp (`services/custom-example`) flattered Giano rather than tested it. This document states
what the rebuilt demo must do and why. The technical detail lives in
[`specs/DEMO-SPECS.md`](./DEMO-SPECS.md); the planning record is
`openspec/changes/rebuild-custom-example-demo/`.

Status: **requirements, agreed** (2026-09-15/16). [§6](#6-open-points) lists what is still open.

---

## Contents

1. [The problem](#1-the-problem)
2. [Goal and scope](#2-goal-and-scope)
3. [Key decisions](#3-key-decisions)
4. [Requirements](#4-requirements)
5. [Giano findings surfaced while specifying the demo](#5-giano-findings-surfaced-while-specifying-the-demo)
6. [Open points](#6-open-points)
7. [Glossary](#7-glossary)

---

## 1. The problem

**The demo did not exercise Giano the way a client would.** It imported a workspace package no
client installs, reached six of roughly thirty-five public SDK surfaces, showed failures as toasts
that vanished, hard-wired exactly two chains, had no unsponsored path, and hid its outcomes in the
console. An integration defect would show up at a tenant before it showed up here.

**A demo that only shows the happy path teaches nothing about setup.** Most integration failures
are deployment mistakes — a dApp origin missing from an allow-list, a COOP header, an RPC pointed at
the wrong network — and today each surfaces as a 15 s or 120 s timeout with no explanation.

**The demo is also the documentation.** `DEVELOPER-GUIDE.md` §4 and `INTEGRATION.md` §9 show code
that no shipped application ran. Snippets drift; a living reference does not.

## 2. Goal and scope

### 2.1 Goal

A dApp that behaves as **any client application**, with no exceptions or privileges, whose purpose is
to **challenge Giano and surface issues**. Where a use case can be exercised in a way that stresses
Giano rather than flatters it, that is how it is built.

### 2.2 In scope

Rebuilding `services/custom-example`; the container contract that lets one image serve every
deployment and both tenant shapes; deploying Giano's test ERC-20 deterministically to every testnet;
converging `DEVELOPER-GUIDE.md` and `INTEGRATION.md` on the demo's code; keeping the Playwright
suite working and giving the demo its own local origins.

### 2.3 Out of scope

Changing Giano core (connector, wallet-kit, wallet-web, wallet-api). Gaps found are written up in
[§5](#5-giano-findings-surfaced-while-specifying-the-demo) and handed on. Building a BYO wallet UI,
a balances/history product, tenant onboarding, or a design system.

## 3. Key decisions

| # | Decision | Why |
|---|---|---|
| K1 | **Published surface only.** The demo imports Giano through `@appliedblockchain/giano-connector`'s default entry point and nothing else; enforced by lint. | A demo that reaches past the published surface validates something no client can reproduce (R2). |
| K2 | **Chakra UI, no custom CSS.** Components and theme tokens only; brand lives in one file. | Cleaner code beats design fidelity; the component library has first-class GenAI tooling (R4, R5). |
| K3 | **The ledger is the record; there are no toasts.** Every action appends an entry with its evidence; entries persist and export. | An issue must be reportable from what is displayed (R9). |
| K4 | **Chain selection is provider selection.** One provider per chain over one wallet origin; a switch is a refusal to demonstrate, not a feature to hide. | That is Giano's real mechanism (MC-01); the demo shows it rather than papering over it (R10). |
| K5 | **Identity is asserted, not assumed.** Every chain's granted account is compared with the first; disagreement is a persistent violation. | The dApp cannot compute the address; agreement of grants is the observable proof (R11). |
| K6 | **Gas payer is declared by the user and attributed from the receipt.** | The dApp cannot request self-payment (G1); declaring the expectation and flagging the disagreement is what a client can actually do (R12). |
| K7 | **A setup preflight runs at load.** Targeted checks (one per concern, plus one per configured chain and default token) replace the timeouts a misconfiguration otherwise produces. | R7 and R16 applied to setup rather than only to actions. |
| K8 | **Build once, deploy anywhere, with runtime injection.** `/config.js` rendered at container start from `GIANO_*`, validated in the browser; no secrets in the bundle. | One image, both tenant shapes, by environment alone (R16, R17). Baanx's pattern. |
| K9 | **The demo gets its own local origins** (`demo.localhost`, `demo-byo.localhost`). | The fixture and the demo used to share ports and Playwright silently adopted the wrong one. |

## 4. Requirements

Numbering follows the ticket. **R8 and R18 were not defined in the ticket**; R18 is referenced as
"the natural place is `e2e/`" and is taken to mean automated coverage of the demo.

| # | Requirement |
|---|---|
| R1 | Rebuild `services/custom-example`. |
| R2 | Build only on the published Giano packages, through their public entry points — the same artifacts a client installs. No imports into workspace internals. |
| R3 | The demo is the reference integration: its code is what `DEVELOPER-GUIDE.md` and `INTEGRATION.md` describe. Divergence is a defect in one of them. |
| R4 | Writing custom CSS is forbidden. Only what the component library provides. |
| R5 | Applied Blockchain branding. |
| R6 | The demo uses Giano for all of its use cases; every method the SDK exposes is reachable from the UI. |
| R7 | Failure paths are first-class: user rejection, popup blocked, wrong chain, insufficient balance, unavailable chain — and, added in review, disallowed origin, session ended, receipt timeout, malformed input. |
| R9 | Every outcome is visible and attributable — result, userop hash, transaction hash, receipt, balance delta, full errors — and persists on screen. Toasts are not sufficient. |
| R10 | The user selects the blockchain in the UI. |
| R11 | Switching chain preserves the smart-account address; a violation is obvious, not silent. |
| R12 | Both sponsored and unsponsored transactions are reachable. |
| R13 | A section dedicated to an ERC-20 token, with a default address; Giano's test ERC-20 deployed with CREATE2 to each testnet so the address is the same everywhere. |
| R14 | The user can mint the default test ERC-20. |
| R15 | Wallet-management operations are accessible. |
| R16 | Build once, deploy anywhere: configuration resolves at runtime; one image serves every deployment and both tenant shapes. |
| R17 | No secrets in the bundle. |
| R18 *(assumed)* | Automated coverage of the demo in `e2e/`, without breaking the existing suite. |

Acceptance scenarios for each are the delta specs in
`openspec/changes/rebuild-custom-example-demo/specs/` (`demo-dapp`, `demo-deployment`,
`test-erc20-registry`).

## 5. Giano findings surfaced while specifying the demo

These are defects or gaps in Giano itself. The demo shows them; it does not fix them.

| # | Finding | Suggested follow-up |
|---|---|---|
| G1 | **No client-side way to request an unsponsored operation.** With `sponsorship: service` a refusal ends in Close; a user with native balance cannot pay. | A review-screen fallback ("pay the fee from this wallet") and/or an EIP-5792-style capability the dApp can send. |
| G2 | **dApps have no key-free read path.** `POST /v1/rpc/:chainId` is wallet-origin-bound, so a dApp on a testnet must ship its own RPC URL. | Accept `corsOrigins` on the read relay. |
| G3 | **Receipt polling is the only cross-origin fetch a dApp makes** and is easy to omit from CSP; the connector surfaces a 120 s timeout instead of a clear error. | Detect a blocked fetch and fail fast with a typed error. |
| G4 | **`waitForUserOperationReceipt` returns `unknown`.** Every integrator casts. | Publish a `UserOperationReceipt` type on the provider. |
| G5 | **A sponsorship refusal is indistinguishable from a user rejection at the dApp.** Both are 4001. | A typed `data.reason` on the 4001 when the wallet refused before approval. |
| G6 | **The dApp allow-list is not discoverable before connecting.** The most common deployment mistake is diagnosable only after a popup. | A public well-known document listing allowed dApp origins per tenant. |
| G7 | **`createGianoConnector.connect()` ignores wagmi's `isReconnecting`.** wagmi's default mount-time reconnect calls `isAuthorized()` (true once a session is cached) then `connect()`, which always issues `eth_requestAccounts`: a second Connect popup opens and blocks every other request ("another request is already pending"). Found by the demo's Adapters card on 2026-09-16. | On `isReconnecting`, answer from `eth_accounts` instead of `eth_requestAccounts`. The demo works around it with `reconnectOnMount={false}`. |
| G8 | **wallet-web serves its HTML shell without `Cache-Control: no-cache`.** After a wallet-web redeploy a browser that has the wallet origin cached keeps running the previous bundle (and its previous config rules) until a hard reload — the popup showed "wallet misconfigured" against a config the new build accepts. Found during the demo review on 2026-09-16. | `expires epoch` / `Cache-Control: no-cache` on `/` and `/index.html` in wallet-web's nginx template (the demo image already does this). |

## 6. Open points

- **Brand tokens.** `src/theme.ts` carries placeholder values under the final token names until the
  Applied Edge Design System export is available.
- **Test ERC-20 on testnets** (R13) needs a funded deployer key for Base Sepolia and Ethereum Sepolia.
  Until deployed, `defaultToken` is unset for those chains and the ERC-20 card opens empty there.
- **G5** blocks a demo that explains a refusal rather than annotating it; a connector or wallet-kit
  change, tracked separately.
- **Secrets client.** `@appliedblockchain/secret-manager-client` is not used: the image has no Node
  process and, by R17, no secret to read. Adopting it means a Node edge server for keyed RPC
  upstreams — a decision, not an omission.

## 7. Glossary

- **Wallet origin** — the tenant's browser origin that holds the passkey and runs the popup.
- **Thin SDK** — `@appliedblockchain/giano-connector`: the dApp-side EIP-1193 provider over the popup transport.
- **Ledger** — the demo's persistent, exportable record of every action and its evidence.
- **Preflight** — the demo's load-time setup checks.
- **Declared / actual payer** — what the user expected to pay for gas vs. what the receipt shows.
- **Violation** — a broken Giano invariant observed by the demo, rendered as a persistent banner and a ledger row.
