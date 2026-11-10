# Tasks

## 1. Baseline

- [x] 1.1 On the unmodified branch, run `pnpm lint`, `pnpm -F @appliedblockchain/giano-contracts test`, `test:deploy`, `typecheck`, `release:verify`, `pnpm -F @appliedblockchain/giano-wallet-api test` and `typecheck`. Record any failure that already exists. Done when the results are saved in the scratchpad.

## 2. Release fingerprints (PR 2, design D1 and D7)

- [x] 2.1 Extend the release tooling so that compiling a release's `standard-input.json` yields, per deployable contract, the runtime bytecode and `immutableReferences`. Verify with a unit test that the factory's `implementation` immutable and both UUPS `__self` immutables are reported.
- [x] 2.2 Add a generator (`pnpm gen:releases`) that writes `releases.ts` with `{ contract, release, immutables, fingerprint }` for every release, plus a `releaseOf(kind, runtimeCode)` helper. Verify that running it twice gives no diff, and that `releaseOf` recognises code deployed by `local:deploy` for every core contract.
- [x] 2.3 Add a test that fails when any release contract has an immutable reference without a registered semantic check (design risk 1). Verify it passes for `v1` and `v2`, and fails when a check is removed.
- [ ] 2.4 CI: in `determinism.yml`, regenerate `releases.ts` and fail on drift. Verify by pushing the layer and checking that the job is green.

## 3. Network classes, overrides and the deployment guard (PR 3, design D2–D5)

- [ ] 3.1 `deploy/config.ts`: replace `CANONICAL_DEPLOYER` with `DEPLOYERS { mainnet, testnet, local }`, where `local` is `0x…dEaD` and the others are `null`, and reject equal mainnet and testnet values. Verify with `test:deploy` that local chains still impersonate `0x…dEaD`, and that `local:deploy` produces the same addresses as before (`e2e/devnet/addresses.json` unchanged).
- [ ] 3.2 `deploy/profiles.ts`: add the required `network` and the optional `addresses` block (design D3). Set `"network": "testnet"` and `"release": "v2"` in both shipped profiles. Verify with `profiles.test.ts` cases: a missing class, an unknown class, an unknown override key, and a valid override.
- [ ] 3.3 Planner: compute expected and actual addresses per contract, classify deviations (override, non-canonical signer, unexpected existing code), and verify override targets with `releaseOf` and the semantic checks before signing. Verify with `preflight.test.ts` cases for each deviation kind, and for an override with no code or foreign code.
- [ ] 3.4 Deploy with overrides: skip the overridden contracts and wire dependants to them (the factory's implementation argument, the proxy's implementation). Verify with an `integration.test.ts` run on anvil that overrides the wallet implementation and the paymaster proxy.
- [ ] 3.5 Mainnet guard in `deploy/guided.ts`: require the signer to be `DEPLOYERS.mainnet`, or else treat it as a deviation; show the warning block; require `deviate <profile>`; refuse non-interactive deviations. Testnet only reports. Add `--allow-deviation` to `deploy:cli core`. Verify with tests covering the scenarios in `specs/contract-deployment/spec.md`: a canonical run, a different key, non-interactive, and a testnet override.
- [ ] 3.6 Refuse to sign for a class whose deployer is `null`, while still printing the plan. Verify with a test against a mainnet profile while `mainnet` is `null`.
- [ ] 3.7 Records v2: add `network`, per-contract `deterministic` and `expected`, and `deviations` (design D5). Update `records.ts` and `operations.ts`. Verify with `deploy.test.ts`, which checks that a confirmed deviation is written.
- [ ] 3.8 `generate-addresses.ts`: drop the canonical-deployer and canonical-address checks, and use `releaseOf` for code. Verify with tests for a record carrying an overridden address (accepted) and a record with foreign code (rejected), and that `pnpm gen:addresses` leaves no drift.
- [ ] 3.9 Remove `canonical.ts`, `scripts/generate-canonical.ts` and the `CANONICAL_*` exports, and export `releaseOf` and the fingerprints from `index.ts`. Fix `deploy-local.ts` and every in-repo import. Add a major changeset that names the replacements. Verify with `pnpm -r typecheck` and with `grep -r CANONICAL_FACTORY`, which should match nothing outside the CHANGELOG.
- [ ] 3.10 CI: in `determinism.yml`, assert the CREATE3 math and the `releaseOf` result for `local` and for each class deployer that is set (design D7). Verify with a green run on the layer.
- [ ] 3.11 Rewrite the contracts README sections "Canonical addresses" and "Deploying", and `deploy/contracts/README.md`, for classes, overrides and the mainnet guard. Verify by following the `--plan` commands as written against Base Sepolia (read-only).

## 4. wallet-api and doctor (PR 4, design D6)

- [ ] 4.1 `chain-verify.ts`: remove `factory-not-canonical`; compare `factory.implementation()` with the chain's resolved implementation; use `releaseOf` for the factory and the implementation (`code-not-release`, with the kind); check that the paymaster proxy's implementation slot holds paymaster release code. Update `describeFailure`. Verify with `pnpm -F @appliedblockchain/giano-wallet-api test`, including new cases: two chains with different paymaster addresses are both admitted, and diverging probe addresses refuse start-up.
- [ ] 4.2 Let `GIANO_CHAINS` `walletApi` carry an optional `implementation`, falling back to the registry. Verify with a config test, and with `openapi:check` if the schema is published.
- [ ] 4.3 `openapi/generate.ts`: replace `CANONICAL_FACTORY` with a fixed dummy address. Verify that `openapi:check` passes with no diff.
- [ ] 4.4 `scripts/doctor.ts`: replace the canonical comparisons with `releaseOf` and the semantic checks. Report whether each address is deterministic for the class. With a profile, flag mainnet deviations missing from the record. Verify with `pnpm run doctor chain` against the e2e devnet (all ok), and with a doctor test for an undeclared deviation.
- [ ] 4.5 Run the e2e suite against the stack built from this layer. Verify that Playwright is green, re-running once for the known watcher-stall flake before investigating.

## 5. Docs and specs (PR 5)

- [ ] 5.1 `specs/MULTICHAIN_REQUIREMENTS.md`: amend MC-17, MC-19, MC-20, MC-27 and MC-28 to read "the deployment's registered addresses, verified by release code" instead of a constant. Scope MC-16 and MC-31 to the chains one deployment serves, and note that testnet and mainnet addresses differ. Verify through review: no MC requirement refers to `CANONICAL_FACTORY`.
- [ ] 5.2 `specs/CHAIN-ADOPTION.md`, `specs/INTEGRATION.md`, `specs/DEVELOPER-GUIDE.md`, `specs/INFRASTRUCTURE.md` §13.1 and the Helm `values.yaml` comments: update them for the per-class deployers and per-chain addresses. Verify with `grep -rn "canonical deployer\|CANONICAL_" specs deploy/helm`, which should show only the updated wording.
- [ ] 5.3 `docs/key-ceremony.md`: list the two canonical deployers as development-team keys in 1Password, out of ABIP-8 scope, with the reason and their 1Password items. Remove the canonical deployer from the ceremony runbook table, and reword the Helm/DevOps references (the `production-key-ceremony` delta). Verify against the delta's scenarios.
- [ ] 5.4 Check that the deploy wizard and `deploy:cli` never print the deployer key or write it to a record or file. Verify with a test that greps a run's output and record for the key.

## Workflow follow-up

- After the development team creates both deployer keys in 1Password, set `DEPLOYERS.testnet` and `DEPLOYERS.mainnet` in a PR that names both 1Password items.
- Add mainnet profiles (`network: "mainnet"`) once the chains are chosen.
- Archive this change with `openspec archive per-chain-contract-addresses` after the stack merges.

## 6. Review fixes (PR 196)

- [x] 6.1 `releaseOf(contract, code, address?)`: refuse code whose ranges of one immutable differ, and, with an address, code whose `__self` ranges are not that address. Verify with unit tests for a modified `__self` and for diverging factory `implementation` ranges.
- [ ] 6.2 Planner and preflight: pass the address to `releaseOf`; require release `ERC1967Proxy` code at the proxy and bind the proxy's implementation slot to the planned implementation, overrides included; drop `timelock` from the override keys. Verify with `plan.test.ts` cases for a proxy pointing elsewhere and a timelock override key refused.
- [ ] 6.3 `deploy:cli core`: remove `--allow-deviation`, and always refuse a mainnet deviation, pointing at the wizard. Verify with a `deviationGate` test.
- [ ] 6.4 Refuse a deployer (the signer, or a configured class deployer) as `ROLE_ADMIN` on non-local chains, and an existing proxy on which one holds it. Verify with tests.
- [ ] 6.5 `gen:addresses`: refuse a Giano contract field in `address-overrides.json`; treat a record with `network: "mainnet"` as R-29 production. `deploy:cli testing` refuses a mainnet-class chain. Verify with `registry.test.ts` cases.
- [ ] 6.6 wallet-api: compare a recovering chain's probe address with the served chains' before serving it; pass addresses to `releaseOf`; warn when a chain has no implementation to compare. Verify with a test where a recovering chain with another probe stays unavailable.
- [ ] 6.7 doctor: the same `releaseOf` address check, and R-29 for a `--chain` mainnet profile.
- [ ] 6.8 Docs: drop `--allow-deviation` and the timelock override from the READMEs and specs.

## 7. Review fixes (stack review)

- [ ] 7.1 `releasesOf(contract, code, address?)` returns every release whose code matches; `releaseOf` takes the expected release and otherwise returns the newest. The planner, `deployCore` and `check:determinism` pass the release they expect. Verify with a unit test for two releases that share a fingerprint.
- [ ] 7.2 `deviationGate` gates only runs that sign, and only deviations the record does not already list as confirmed for the same contract and address. Verify with `plan.test.ts` cases for a verify-only run and a confirmed deviation.
- [ ] 7.3 `recordDeviations` keeps one entry per contract and address, whatever the reason; `record.deployer` changes only when a run deploys something.
- [ ] 7.4 A recorded upgrade target at CREATE3(class deployer, versioned label) is deterministic for `planCore`, `deployCore` and doctor (`placementOf`), and is exempt from the selected-release check. `upgrade --execute` records it with its placement.
- [ ] 7.5 `deploy:cli upgrade` refuses a non-canonical key on a mainnet and records the deviation on other classes (`upgradeDeviation`), before deploying.
- [ ] 7.6 wallet-api admits a recovering chain only after a complete verification: no failure of any kind and a probe address (`recoveryVerified`).
- [ ] 7.7 A keyless plan checks the class deployer's balance; the wizard explains an unreadable deployment record.
- [ ] 7.8 One ERC-1967 implementation reader (`erc1967.ts`) for the planner, preflight, doctor and wallet-api; one changeset per feature.

## 8. Review fixes (second stack review)

- [ ] 8.1 Spec and D4: the expected address of a recorded canonical upgrade target is its versioned label's, and the actual address resolves override, recorded, expected, signer, so a keyless run verifies a recorded non-canonical deployment where it is. Add the post-upgrade and keyless-recorded scenarios.
- [ ] 8.2 `integration.test.ts` passes the release it deployed (`v2`) to `releaseOf`.
- [ ] 8.3 `gen:addresses` accepts a recorded release that is any of the releases sharing the fingerprint. Verify with a `registry.test.ts` case for a release that leaves contracts unchanged.
- [ ] 8.4 `deploy:cli` refuses a deployment record that states another network class than the one it resolved, before any command proceeds. Verify with a CLI test.
- [ ] 8.5 `deploy:cli core` runs `verifyCoreState` (implementation, ROLE_ADMIN, EntryPoint, fees, no deployer holding ROLE_ADMIN) before `deployCore`, including verify-only runs; its fees are the flags, else the profile's. Verify with a `verifyCoreState` test for the CLI's configuration.
- [ ] 8.6 The deployer image and Helm Job accept the chain's profile and committed record (`CHAIN_PROFILE_JSON`, `DEPLOYMENT_RECORD_JSON`; `deployer.chainProfile`, `deployer.deploymentRecord`), so a chain at non-deterministic addresses is verified where it is.
- [ ] 8.7 wallet-api compares a recovering chain with the probe it was admitted with, and seeds the served probes only from completed boot verifications (`recoveryVerified`).
