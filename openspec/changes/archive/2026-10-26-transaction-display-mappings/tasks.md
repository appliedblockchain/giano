## 1. Engine spike and package scaffold

- [x] 1.1 Create `packages/tx-describe` (`@appliedblockchain/giano-tx-describe`) from the `packages/wallet-transport` layout: package.json (ESM+CJS exports, `sideEffects: false`, GitHub Packages publishConfig), `tsup.config.ts`, `tsconfig.json`, `src/index.ts`, vitest.
- [x] 1.2 Add `@ethereum-sourcify/clear-signing` pinned exactly to 0.2.2 and write `src/engine.ts`, the only module that imports it. Spike bar (design D2): accepts caller-supplied descriptors with no network lookup; validates with path-addressed issues; formats a tenant ERC-20 descriptor and a native transfer in a test. Record the outcome in a short note at the top of `src/engine.ts`.
- [x] 1.3 (not needed — spike passed) If the spike fails the bar, implement `src/engine.ts` in-house for the ERC-7730 subset (`raw`, `amount`, `tokenAmount`, `addressName`, `date`, `enum`) with `viem` as a peer dependency and the EIP's JSON schema vendored under `src/schema/`; drop the external dependency. Skip if 1.2 passed.
- [x] 1.4 Confirm the built output has no `@appliedblockchain/giano-*` import and no fetch/RPC code path; add a test that asserts the package.json dependencies contain no Giano package (spec: library is independent).

## 2. Library API

- [x] 2.1 Define and export the public types in `src/types.ts`: `TransactionInput`, `Mapping` (ERC-7730 descriptor), `DescribeOptions` (`mappings`, `builtins`, `nativeCurrency`, `resolveToken`), `TransactionDescription` (`described` with intent, fields, contract, function, source `mapping | generic | native`, warnings; `unknown` with reason `no-mapping | decode-failed | contract-creation`, selector, contract, raw).
- [x] 2.2 Implement `validateMapping(json)` returning `{ ok, issues: [{ path, message }] }`, accepting signature and selector function keys and normalising signatures to selectors.
- [x] 2.3 Implement `describeTransaction(tx, options)`: selection by `(chainId, to, selector)` with caller mappings before built-ins, native transfer for empty data, extra native-amount field when a call carries value, explicit unknown for no mapping / decode failure / contract creation / malformed input, never throws.
- [x] 2.4 Add built-in generic descriptors in `src/builtins/` for ERC-20 `transfer`, `approve`, `transferFrom` and ERC-721 `transferFrom`, `safeTransferFrom` (both arities), `approve`, `setApprovalForAll`, each producing source `generic` and a `generic-interface` warning; honour `builtins: false`.
- [x] 2.5 Implement token formatting through the optional `resolveToken` hook: scaled amount with symbol when it answers; unscaled amount plus token address and a `token-unresolved` warning when absent, empty or rejecting.
- [x] 2.6 Tests under `test/`: one scenario per spec scenario in `transaction-description` (tenant mapping, same mapping two calls, chain mismatch, native value on a call, generic fallback, caller wins, builtins disabled, native transfer with custom currency, no mapping, decode failed, contract creation, resolver answers, resolver fails, garbage input, determinism); snapshot the built-ins' intents.
- [x] 2.7 Write `packages/tx-describe/README.md`: purpose, R1 statement, API, a complete ERC-20 descriptor example, link to the public ERC-7730 registry.

## 3. wallet-api: storage and admin CRUD

- [x] 3.1 Add `services/wallet-api/migrations/0006_tx_mappings.sql` creating `tenant_tx_mappings` (unique on tenant, chain, contract) and `tenant_tx_mappings_history` (action `put | delete`, nullable descriptor, index on tenant, chain, created_at desc) with header comments in the style of `0003_paymaster.sql`; mirror both tables in `src/db/schema.ts`.
- [x] 3.2 Add `@appliedblockchain/giano-tx-describe` as `workspace:^` and write `src/services/tx-mappings.ts`: contract address normalisation, `validateMapping` wrapper, deployment-binding check against `(chainId, contract)`, `writeMapping` / `deleteMapping` in one transaction with history, `listForServing` that re-validates rows and returns valid descriptors plus a list of invalid keys for logging.
- [x] 3.3 Write `src/routes/admin-tx-mappings.ts` with `requireAdmin` + `requireChain`: `GET /v1/admin/tx-mappings`, `GET /v1/admin/tx-mappings/history` (paginated, newest first), `GET|PUT|DELETE /v1/admin/tx-mappings/:contract`; PUT body limit 64 KiB, 400 with `issues[{path,message}]` on any violation, 404 for other tenants' rows; register in `src/app.ts`.
- [x] 3.4 Write `src/routes/tx-mappings.ts` with `requireTenant` + `requireChain`: `GET /v1/tx-mappings?chainId=` returning `{ chainId, mappings, updatedAt }`, `Cache-Control: private, max-age=60`, invalid rows omitted and logged with tenant, chain, contract; register in `src/app.ts`.
- [x] 3.5 Tests `test/tx-mappings.test.ts` against the testcontainers setup: valid write and read-back, binding mismatch 400, invalid descriptor 400 with paths, replace keeps history, delete 204 then 404, cross-tenant 404 both ways, list per chain, history order and key hash, wallet read 200 with mappings, 403 unknown Origin, 200 empty list, stale descriptor omitted from serving and flagged in admin list.
- [x] 3.6 Run `pnpm --filter @appliedblockchain/giano-wallet-api openapi` and commit the regenerated `openapi/openapi.json`; `openapi:check` passes.

## 4. wallet-kit: `describeTransaction` and native currency

- [x] 4.1 Add optional `nativeCurrency: { symbol, decimals }` to the shared chain descriptor schema in `packages/contracts/chains.ts` and to `WalletChainConfig` in `packages/wallet-kit/src/config.ts`, default `{ ETH, 18 }`; `buildRuntime` in `src/runtimes.ts` passes it to `defineChain` instead of the hard-coded ETH.
- [x] 4.2 Add `@appliedblockchain/giano-tx-describe` as `workspace:^` to wallet-kit and write `src/describe.ts`: per-runtime mapping fetch from `{walletApiUrl}/v1/tx-mappings?chainId=` with 3 s timeout, 60 s cache and stale-on-failure plus a `mappings-unavailable` warning; token resolver over `publicClient` (`symbol()`, `decimals()`, 3 s timeout, per-address cache); merge with built-ins; never rejects.
- [x] 4.3 Expose `describeTransaction(tx)` on `WalletRuntime` and wire it in `buildRuntime`; export the description types from the kit's root entry for UI consumers.
- [x] 4.4 Tests in `packages/wallet-kit/test/`: tenant mapping applied, service unreachable degrades to built-ins with warning, token read failure degrades with warning, mappings fetched once within the cache window, custom native currency reaches the description.
- [x] 4.5 Pass `nativeCurrency` through `services/wallet-web/docker/config*.json.template` and `docker/entrypoint.sh` from an optional `GIANO_NATIVE_CURRENCY_SYMBOL` / `GIANO_NATIVE_CURRENCY_DECIMALS` pair; document defaults.

## 5. wallet-web review screen

- [x] 5.1 Rewrite `services/wallet-web/src/views/ReviewTransaction.tsx` around `runtime.describeTransaction(tx)` run concurrently with `checkSponsorship`: intent (`data-testid="tx-intent"`), fields (`data-testid="tx-field"`), native value in the chain's currency, generic-interface note (`data-testid="tx-generic-note"`), collapsed technical details for contract, signature and calldata.
- [x] 5.2 Implement the unknown branch: warning card (`data-testid="tx-unknown"`, `data-reason`), plain-words reason, selector and contract when known, raw value and calldata (`data-testid="tx-raw"`); no guessed function name or argument list anywhere.
- [x] 5.3 Gate the approve control on both the description settling and the pre-flight resolving; show a "preparing the transaction summary" indicator while the description is pending.
- [x] 5.4 Remove the two-ABI decode and the `@appliedblockchain/giano-contracts` dependency from wallet-web's package.json; add the one new style class for the warning card in `src/styles.css`; `pnpm --filter @appliedblockchain/giano-wallet-web build` passes.

## 6. BYO wallet and end-to-end

- [x] 6.1 Update `e2e/wallet-byo/src/views.ts` and `main.ts` to call `pending.runtime.describeTransaction` and render the intent under `data-testid="byo-tx-intent"`, falling back to the existing raw dump only for unknown results.
- [x] 6.2 In e2e setup, publish an ERC-7730 descriptor for the demo ERC-20 on the devnet chain through `PUT /v1/admin/tx-mappings/:contract` with the e2e tenant's admin key (design D10).
- [x] 6.3 Extend `e2e/tests/wallet-flow.spec.ts`: stock wallet shows a transfer intent and no `tx-raw` element for the demo transfer; BYO wallet shows a non-empty `byo-tx-intent`; an unmapped call shows `tx-unknown` with `tx-raw`.
- [x] 6.4 Run the Playwright suite against the compose e2e stack and fix regressions.

## 7. Release wiring and docs

- [x] 7.1 Add the new package to the changesets `fixed` group in `.changeset/config.json` and to the package build/test steps in `.github/workflows/ci.yml`; add a changeset (minor: new package, kit runtime method, chain `nativeCurrency`; patch: wallet-api routes).
- [x] 7.2 Document tenant transaction mappings in `specs/DEVELOPER-GUIDE.md` (new Part C section next to 5.6 sponsorship: routes, a worked ERC-20 descriptor, registry link, validation errors) and reference it from `specs/INTEGRATION.md`.
- [x] 7.3 Update `specs/WALLET-SDK-SPECS.md` (runtime surface gains `describeTransaction`, chain descriptor gains `nativeCurrency`) and the review step in `specs/TRANSACTION-SUBMISSION-FLOW.md`.
- [x] 7.4 Run `pnpm -r build`, `pnpm -r test` and `pnpm --filter @appliedblockchain/giano-wallet-api openapi:check`; run `openspec validate transaction-display-mappings --strict`.
