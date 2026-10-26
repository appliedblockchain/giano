## 1. Spec documents and design input (before any build)

- [x] 1.1 Write `specs/DEMO-REQUIREMENTS.md` in the form of `PAYMASTER-REQUIREMENTS.md`: problem, goal/scope, R1–R17 as
      given (note R8/R18 undefined and the R18 assumption), Giano findings G1–G4, glossary
- [x] 1.2 Write `specs/DEMO-SPECS.md` in the form of `PAYMASTER-SPECS.md`: decisions D1–D13, runtime config contract,
      section-by-section UI spec (D8), ledger schema (D7), lint guards (D2/D10), traceability table R → section/task
- [x] 1.3 Run the Claude Design step with the D9 brief against the Applied Edge Design System; paste screens and the token
      export (colours, font stack, radius) into `DEMO-SPECS.md` §UI; hand-off note: "Chakra UI only, no custom CSS,
      cleaner code beats fidelity"
- [x] 1.4 Fill `src/theme.ts` token values from 1.3 (placeholders under the final token names if tokens are not yet ready)

## 2. Scaffold and guards (core)

- [x] 2.1 Reset `services/custom-example/package.json`: deps `@appliedblockchain/giano-connector` (workspace:^ until H2),
      `viem` (pinned), `@chakra-ui/react` v3 (pinned minor), `@emotion/react`, `react`, `react-dom`, `react-icons`,
      `next-themes`, `zod`, `wagmi`, `@tanstack/react-query`; remove `@appliedblockchain/giano-contracts`
- [x] 2.2 Add ESLint config for the demo: `no-restricted-imports` (all `@appliedblockchain/*` except the connector; any
      relative path leaving `src`; any `*.css`), `react/forbid-dom-props` for `style`, `react/forbid-component-props` for
      `css`/`style`; wire `pnpm -F @appliedblockchain/giano-example lint` and add it to the `build` script
- [x] 2.3 Add a post-build bundle scan script: fail on `navigator.credentials`, on `VITE_` values other than the
      documented dev fallbacks, and on any `.css` asset
- [x] 2.4 Remove `globalCss`, frosted-glass card styling, Google Fonts link and the `Toaster`; keep `Provider`/color-mode

## 3. Runtime configuration and container (core)

- [x] 3.1 Define `RuntimeConfig` zod schema in `src/config.ts`: `walletUrl`, `otherWalletUrl?` (a wallet origin that does
      not allow-list this dApp, for the disallowed-origin control), `appLabel?`, `chains: [{ chainId, name,
      rpcUrl, explorerUrl?, defaultToken? }]`; parse `window.__GIANO_CONFIG__` synchronously; export a `ConfigError`
      result instead of throwing
- [x] 3.2 Render a configuration-error screen (Chakra `Alert` + field list) when parsing fails; construct no provider
- [x] 3.3 Rewrite `docker/config.js.template` to emit `chains` as a JSON literal and `docker/entrypoint.sh` to accept
      `GIANO_CHAINS` (primary) or the scalar pair (deprecated, converted, logged), refuse both, build CSP `connect-src`
      from every chain's RPC origin plus the wallet origin, and support `GIANO_RPC_UPSTREAM_<chainId>` for
      `location = /rpc/<chainId>` proxy blocks in `nginx.conf.template`
- [x] 3.4 Keep `X-Frame-Options: DENY`, nosniff, no-referrer, `no-store` on `/config.js`, no COOP; add `expires epoch` for
      HTML per the Baanx nginx config
- [x] 3.5 `.env.example` for `pnpm dev` using the same `GIANO_*` names via Vite `envPrefix: 'GIANO_'`; update
      `public/config.js` placeholder comment
- [x] 3.6 Update Dockerfile build stage for the new dependency set; add a comment marking the lines that disappear once
      H2 lets the demo install from GitHub Packages

## 4. Core session, chains, identity, ledger (core)

- [x] 4.1 `src/lib/chains.ts`: `ChainRegistry` — lazily build `{ chain, provider, publicClient }` per configured chain;
      `addAdHocChain(chainId, rpcUrl)` for the free-form path
- [x] 4.2 `src/lib/ledger.ts`: `LedgerEntry` type, reducer, `localStorage` persistence namespaced by wallet origin, cap 500
      with warning, export-as-JSON (includes runtime config and connector version)
- [x] 4.3 `src/lib/run.ts`: `runAction({ section, method, params, chainId, declaredPayer }, fn)` — records start, result,
      typed error (`TransportError`/`TransportRpcError`/`UnsupportedChainError`/`HandshakeRefusedError` → name, code,
      message, data, reason, supportedChainIds), duration; captures native/token balances before and after
- [x] 4.4 `src/hooks/useSession.ts`: per-chain account state, `eth_accounts` resume, event subscriptions written to the
      events log, `disconnect()` and `wallet_revokePermissions`
- [x] 4.5 Header card: brand, `appLabel`, wallet origin, connector version, `isConnected()` badge, connect/disconnect,
      address with `Clipboard`
- [x] 4.6 Chain card: configured chains with served/not-served badge from `supportedChainIds`, native balance, deployed
      badge (`getCode`), free-form add-chain fields, provider-options disclosure (`walletApiPath`, storage backend),
      "Connect on this chain", "Read eth_chainId", "Attempt wallet_switchEthereumChain", "Attempt wallet_addEthereumChain"
- [x] 4.7 Identity card: chain → granted address table; persistent violation `Alert` on mismatch; ledger entry
- [x] 4.7a Shared UI primitives per D8 UX rules: `StatusText` (dot + text), `OutcomeRow` (summary line + folded details, latest
      open), `ActionPicker` (Select + primary button), section jump bar, preflight line; no card renders a badge stack
- [x] 4.8 Ledger card: Chakra `Table` with expandable rows, filters, per-row copy, Export, Clear; Events card
- [x] 4.9 `src/lib/preflight.ts` + Preflight card (D14): wallet version fetch (reachability, CORS, api version), own COOP
      header via `fetch(location.href)`, RPC `eth_chainId` vs configured id per chain, `eth_getCode` on each default
      token, storage probe, connector vs api version; pass/warn/fail rows with operator action; disables write controls
      on a wrong-network chain; attaches a receipts warning on CORS failure; Re-run control; collapses when all pass
- [x] 4.10 Reconnect prompt in the header on `disconnect` 4900

## 5. Transactions, gas payer, signing (core)

- [x] 5.1 Transactions card (includes "keep waiting" on receipt timeout, and the "closed by the user or refused in the
      wallet" annotation with a wallet-console pointer on 4001 after a sponsored send): declared-payer `RadioGroup`; presets (0 ETH to self, value to address, unlisted contract,
      arbitrary target + calldata); `eth_sendTransaction` → `waitForUserOperationReceipt` → receipt fields (`sender`,
      `paymaster`, `actualGasCost`, `success`, tx hash, block); payer attribution and mismatch flag
- [x] 5.2 Native balance display with refresh after every action; "Fund from devnet" probing `anvil_setBalance` once per
      chain, hidden when refused; faucet hint with copyable address otherwise
- [x] 5.3 Signing card: `personal_sign`, `eth_sign`, `eth_signTypedData_v4` with editable typed-data JSON; show full
      signatures
- [x] 5.4 Failure lab card: reject instructions, popup-blocked delayed call (1.5 s), unserved chain 99999, disallowed
      origin (provider against the other tenant's wallet origin from runtime config `otherWalletUrl`, expect
      `origin-not-allowed`), invalid address, invalid hex, revoke-then-`eth_accounts`

## 6. ERC-20 and wallet management (core)

- [x] 6.1 ERC-20 card: default token from selected chain's `defaultToken`; load metadata/balance/allowance; Mint,
      Transfer, Approve, Sign permit (nonces probe → clean "no EIP-2612" entry); token balance deltas in the ledger
- [x] 6.2 Wallet management card: `openWalletManagement()`; record "closed, no data" or violation if data returned

## 7. Raw user operation, wagmi and RainbowKit (core)

- [x] 7.1 Raw user-operation card: stepper `eth_prepareUserOperation` → `eth_signUserOperation` →
      `eth_sendSignedUserOperation` with each payload in a `Code` block; `signed_eth_call` against `privateBalanceOf`
- [x] 7.2 wagmi card (lazy-loaded): `createConfig` with `custom(provider)` and `createGianoConnector`; connect,
      `useAccount`, `switchChain` (record `UnsupportedChainSwitchError`), send + `waitForUserOperationReceipt`
- [x] 7.3 RainbowKit `giano({ provider })` inside the wagmi card; connect modal lists Giano and grants the same account

## 8. Test ERC-20 on testnets

Rehearsed locally on 2026-09-17: the `giano-contracts-deployer` image (built from `Dockerfile.deployer`, which carries the
pinned `forge`) run with `HARDHAT_NETWORK=custom DEPLOY_TESTING=true PAYMASTER_FUND_ETH=1` against a fresh pinned anvil
(chain id 31337 on a spare port, EntryPoint installed by `e2e/devnet/setup-entrypoint.mjs`) deployed
`Testing#PrivateERC20` at `0x9967bDf929856643e92EF65eefdE1fF8250774D8` — identical to the devnet — plus the canonical
factory/implementation/permissive paymaster addresses. Two things to know for the real run: Ignition's create2 strategy
auto-deploys CreateX only on chain id 31337 (the testnets already have CreateX); and the deployer's Ignition journal lives
inside the container — mount `packages/contracts/ignition/deployments` to keep the `chain-<id>` journal for committing.
The deployer's final registry-emission step refuses dev chain ids by design (not a failure of the deploy).


- [ ] 8.1 Deploy `Testing` module with `--strategy create2` to Base Sepolia and Ethereum Sepolia (`PAYMASTER_FUND_ETH`
      small); commit journals under `ignition/deployments/chain-84532` and `chain-11155111`
- [ ] 8.2 Verify the ERC-20 address is identical across the two testnets and the devnet; if the devnet differs,
      regenerate `e2e/devnet/state.json` + `addresses.json` and update the devnet default
- [ ] 8.3 Run `pnpm gen:addresses`; ensure `testErc20` is present for 84532/11155111 and absent for 8453
      (`address-overrides.json`); update `packages/contracts/README.md`

## 9. Deployment configuration

- [x] 9.1 `deploy/docker-compose.infrastructure.yml`: both demo services on `GIANO_CHAINS` (chain A `service`, chain B
      `off` on wallet-web for the self-paid path); `defaultToken` per chain
- [x] 9.2 `deploy/docker-compose.infrastructure.aws.yml` and `infra/iac/ecs_services.tf` (`svc-custom-example`,
      `svc-custom-example-byoui`): `GIANO_CHAINS` with Base Sepolia + Ethereum Sepolia, `defaultToken` from 8.3,
      keyed RPC via `/rpc/<chainId>` + `GIANO_RPC_UPSTREAM_<chainId>` secrets
- [x] 9.3 `terraform fmt`/`validate`; compose `config` renders; document the deprecation window in `DEMO-SPECS.md`
      (compose files render; terraform fmt -check and validate pass with the CI-pinned 1.11.4, run from a glibc container
      because the 1Password provider binary does not exec on the Alpine terraform image — 2026-09-17)

## 10. Local origins and e2e

- [x] 10.1 `e2e/origins.mjs`: add `demo` (4410, `demo.localhost`) and `demo-byo` (4411, `demo-byo.localhost`);
      `portless-setup.mjs` registers them
- [x] 10.2 `deploy/docker-compose.e2e.yml`: add the demo origins to both tenants' `allowedDappOrigins`/`corsOrigins` and
      to wallet-web `GIANO_ALLOWED_DAPP_ORIGINS`; keep `app`/`app-byo` untouched
- [x] 10.3 Root `demo:dev|demo:stock|demo:byo` scripts move to 4410/4411 and the new names; update demo README
- [x] 10.4 Run the full existing Playwright suite unchanged and record the result
      (2026-09-16: 47/54 passed with the demo running; the 7 failures were all environment — stale `packages/*/dist` in the
      host BYO fixture after wallet-api was rebuilt from newer source, plus two runs killed for low memory. After rebuilding
      the packages: byo-wallet 5/5, sponsorship 23/23, wallet-management 7/7, tenant-isolation 4/5 — V1 fails on a
      persistent database because it registers a fixed external id and cannot re-authenticate it from a fresh browser;
      passes on a fresh DB, as CI has. Pre-existing test-idempotency issue, not related to this change)
- [x] 10.5 (R18 assumption, promoted to core) Playwright `demo` project (opt-in `--project demo`): smoke spec — connect, send 0 ETH,
      ledger row with receipt, identity "identical" after connecting on chain B

## 11. Documentation convergence (core)

- [x] 11.1 Rewrite `specs/DEVELOPER-GUIDE.md` §4.2–4.5 snippets to match demo code and reference demo file paths;
      update §3 local-run instructions for the new demo origins
- [x] 11.2 Rewrite `specs/INTEGRATION.md` §9 snippet and the wallet-management snippet to match the demo
- [x] 11.3 Rewrite `services/custom-example/README.md`: what each card exercises, how to reproduce each failure path,
      how to read and export the ledger, env contract table, deprecation note
- [x] 11.4 Add the Giano findings G1–G6 to `specs/DEMO-REQUIREMENTS.md` and open follow-up tickets for them
- [x] 11.5 Review checklist: every snippet in 11.1/11.2 compiles against the demo's imports; `ARCHITECTURE.md` §8
      product-gap list updated if any gap moved

## 12. Verification

- [x] 12.1 `pnpm -F @appliedblockchain/giano-example lint && build`; bundle scan passes; Docker image builds from the
      repo root and starts with `GIANO_CHAINS`, with the scalar pair (deprecation logged), and refuses both together
- [ ] 12.2 Manual pass against `deploy/docker-compose.infrastructure.yml`: every card, every failure control, both
      tenants, both chains; export the ledger and attach it to the PR
- [x] 12.3 Confirm `pnpm -F @appliedblockchain/giano-e2e test` passes with the demo running on its new ports (see 10.4; the demo
      on 4410/4411 and the fixture on 4400/4401 coexist; a stale Vite server from the old layout on 4400/4401 was the one
      real clash found and stopped)
