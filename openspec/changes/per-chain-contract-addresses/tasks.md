# Tasks

## 1. Baseline

- [ ] 1.1 On the unmodified branch, run `pnpm lint`, `pnpm -F @appliedblockchain/giano-contracts test`, `test:deploy`, `typecheck`, `release:verify`, `pnpm -F @appliedblockchain/giano-wallet-api test` and `typecheck`. Record any failure that already exists. Done when the results are saved in the scratchpad.

## 2. Release fingerprints (PR 2, design D1 and D7)

- [ ] 2.1 Extend the release tooling so that compiling a release's `standard-input.json` yields, per deployable contract, the runtime bytecode and `immutableReferences`. Verify with a unit test that the factory's `implementation` immutable and both UUPS `__self` immutables are reported.
- [ ] 2.2 Add a generator (`pnpm gen:releases`) that writes `releases.ts` with `{ contract, release, immutables, fingerprint }` for every release, plus a `releaseOf(kind, runtimeCode)` helper. Verify that running it twice gives no diff, and that `releaseOf` recognises code deployed by `local:deploy` for every core contract.
- [ ] 2.3 Add a test that fails when any release contract has an immutable reference without a registered semantic check (design risk 1). Verify it passes for `v1` and `v2`, and fails when a check is removed.
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
