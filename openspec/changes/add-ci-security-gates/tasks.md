# Tasks

## 1. Register and Solidity analysis (PR 1)

- [x] 1.1 Add `scripts/check-accepted-findings.mjs` in register mode (D1, D2): validate fields, `AF-NNN` IDs, dates, the 180-day limit, expiry and duplicates; reject `slither-disable` and `aderyn-ignore` comments under `packages/contracts/src`; check that every suppression in `.gitleaks.toml`, `packages/contracts/slither.config.json` and `packages/contracts/aderyn.toml` (each when present) names an existing entry. Verify with `node scripts/check-accepted-findings.mjs` exiting 0 on the committed register.
- [x] 1.2 Add report mode for `slither`, `aderyn`, `pnpm-audit`, `trivy` and `gitleaks` with the match keys in D2. It fails on a missing, empty or invalid report, including a pnpm error object, and prints the entry ID of each accepted finding. Verify with the unit tests in 1.3.
- [x] 1.3 Add `scripts/check-accepted-findings.test.mjs` (`node --test`) covering each scenario of the register requirements in `specs/ci-security-gates/spec.md`: missing owner, expiry over 180 days, expired entry, duplicate ID, suppression without an entry, in-source Solidity suppression, and for each tool a matched, an unmatched, an expired-match and an invalid report. Verify all pass.
- [x] 1.4 Create `security/accepted-findings.json` with AF-006 and AF-007 (`minimatch`, `glob`), owner and expiry set. Verify the register check passes. (Both entries were removed in 1.17.)
- [x] 1.5 Add job `accepted-findings` ("Accepted-findings register") to `ci.yml`: unit tests, then register mode. No `paths` filter. Verify it is green on the PR.
- [x] 1.6 Add job `ci-passed` ("CI passed") to `ci.yml` as in D12: `needs` every other job in the file, runs with `if: always()`, and fails unless every needed job succeeded. `scripts/check-ci-gate.mjs` (with tests) parses `ci.yml` and fails on a job missing from `needs`, a missing `if: always()` or any `continue-on-error`. Verify it is green on the PR, and red on a scratch run where one needed job is made to fail. Scratch run: https://github.com/appliedblockchain/giano/actions/runs/43050281214 (#267).
- [x] 1.7 Add `packages/contracts/requirements-ci.in` (`slither-analyzer==0.11.6`) and the hash-locked `requirements-ci.txt` generated with `uv pip compile … --generate-hashes`. Confirm 0.11.6 was released at least 7 days ago. Verify `pip install --require-hashes -r requirements-ci.txt` succeeds in a clean Python 3.12 venv.
- [x] 1.8 Add `packages/contracts/slither.config.json` and `aderyn.toml` with the scope filters in D3 and a reason for each. Verify a local run reports the same Highs as the trial run (D9) and no finding from `src/testing`, `test/` or `lib/`.
- [x] 1.9 Confirm the two open points of AF-002 and AF-003: the factory's `payable` constructor (L36) and the paymaster's `addStake` (L540) cannot leave ether stuck. If either can, stop and raise it instead of adding the entry.
- [x] 1.10 Add AF-001 to AF-005 to the register with the Slither `id` and the Aderyn path and line from the local run, owner Rui Sereno. Verify report mode passes on both local reports and fails if one entry is removed.
- [x] 1.11 Add job `solidity-analysis` ("Solidity static analysis (Slither, Aderyn)") to `ci.yml` as in D4, and add it to the `needs` of `ci-passed`: Aderyn v0.6.8 binary with recorded sha256, both tools, report mode for each, artifacts uploaded with `if: always()`. Verify the job is green on the PR and the three reports are attached to the run.
- [x] 1.12 Verify the gate fails: on a scratch branch that is never merged, add an unprotected `selfdestruct` or arbitrary `call` to a source contract and confirm the job fails and names the detector. Record the run link in the PR description. Scratch run: https://github.com/appliedblockchain/giano/actions/runs/43050288365 (#268).
- [x] 1.13 Write `security/README.md`: entry fields, the 180-day limit, how to renew, how each tool's finding ID is found. Verify the README example entry passes the register check.
- [x] 1.14 Add the pinning rule in D11 to `docs/abip-compliance.md`, with a table of each tool, its version, release date and where its hash is recorded. Start the table with Slither and Aderyn. Verify both appear with the versions used in `ci.yml`.
- [x] 1.15 Pin every action that the new jobs use to a full commit SHA, with the release as a comment, as #246 does. Extend `scripts/check-ci-gate.mjs` (with tests) to fail on any `uses` in `.github/workflows` that is not a local path, a commit SHA or an image digest (D12). Verify the check passes on every workflow and fails on `actions/checkout@v7`.
- [x] 1.16 Replace the parsing of `slither.config.json` and `aderyn.toml` with a comparison against a fixed copy, apart from the reasons (D3). Verify the committed configs pass, and every changed value, added setting and other TOML or JSON form in the tests fails.
- [x] 1.17 Remove AF-006 and AF-007 from the register, because #260 fixed both advisories by lifting `glob` to 14.0.3 (with `minimatch` 11.0.4). Verify `pnpm audit` reports no advisory in the root workspace and the register check passes.
- [x] 1.18 Make report mode fail on a `slither` or `aderyn` entry that matches no finding in the report (D1), so a stale entry cannot accept a later finding on the same line. Verify with unit tests, that both CI reports still pass, and that the Aderyn report without the AF-004 finding fails and names AF-004.
- [x] 1.19 Extend `scripts/check-ci-gate.mjs` (with tests) to fail on a job `container` or `services` image that is not pinned by digest, and to check the `uses` of every local action a workflow uses (D12). Verify the check passes on every workflow and fails on `container: node:24`.
- [x] 1.20 Make `scripts/check-ci-gate.mjs` (with tests) fail on a local Docker action whose `runs.image` is not a `docker://` image pinned by digest, including a Dockerfile, and check a local action in a folder of `.github/workflows` or reached through `..` (D12). Verify each of the three cases fails and every workflow still passes.

## 2. Dependencies, secrets and source (PR 2)

- [ ] 2.1 Add job `dependency-audit` ("Dependency audit (pnpm audit)") to `ci.yml` as in D5, for the root and `services/custom-example`, and add it to the `needs` of `ci-passed`. Verify it is green on the PR and that the log shows the audit result of both workspaces.
- [ ] 2.2 Extend `.github/dependabot.yml`, which #246 added, with the two npm entries in D6. Verify GitHub reports no configuration error for it in the PR's checks.
- [x] 2.3 Update the ABIP-6 section of `docs/abip-compliance.md`: the audit runs in CI, and accepted residuals live in the register. Verify the doc links resolve.
- [x] 2.4 Add `.gitleaks.toml` that extends the default rules, with one allowlist for the public Anvil keys, and register entry AF-008 for it. Verify the register check passes.
- [ ] 2.5 Add job `secret-scan` ("Secret scan (gitleaks)") to `ci.yml` as in D8, and add it to the `needs` of `ci-passed`: gitleaks binary with recorded sha256, released at least 7 days ago, run with `--ignore-gitleaks-allow`. Add gitleaks to the pinning table. Verify it is green on the PR and passes on the `workflow_call` path.
- [ ] 2.6 Verify the secret gate fails: on a scratch branch that is never merged, commit a fake key that matches a gitleaks rule and confirm the job fails with the secret redacted. Record the run link in the PR description.
- [ ] 2.7 Add `.github/workflows/codeql.yml` as in D7. Verify both matrix legs succeed on the PR and the "CodeQL" check appears.
- [ ] 2.8 After the first CodeQL run on `main`, triage the baseline alerts: fix each one, or dismiss it in GitHub and add a register entry with tool `codeql`. Verify no open high or critical alert remains without an entry.
- [x] 2.9 Add gitleaks rules for RPC provider keys (Infura, Alchemy, QuickNode, Ankr) to `.gitleaks.toml`, and let the register check accept a `[[rules]]` table only with a `giano-` ID and only `id`, `description`, `regex` and `keywords` (D8). Add allowlist AF-010 for the public forge-std Infura key. Verify with unit tests that each rule matches a fake key and captures only the key, and that a rule with a default rule's ID fails.
- [x] 2.10 Pin the actions of `dependency-audit`, `secret-scan` and `codeql.yml` to commit SHAs, as #246 does (D12). Verify `node scripts/check-ci-gate.mjs` passes.
- [x] 2.11 Widen `giano-alchemy-key` to every versioned Alchemy API path (`/v2/`, `/nft/v3/`, `/prices/v1/`) (D8). Verify with unit tests that each form matches and captures only the key.
- [x] 2.12 Clear `https-proxy` and `proxy` on the `pnpm audit` command line (D5). Verify locally that a proxy in `.npmrc` or `pnpm-workspace.yaml` makes the audit fail without the flags and has no effect with them.
- [x] 2.13 Make the secret scan fail on an error line in the gitleaks log, and when gitleaks reports fewer scanned commits than the range has commits that add a line (D8). Verify the count on this branch and on a range of `main` with a clean merge.
- [ ] 2.14 Give the `services/custom-example` Dependabot entry the `github-packages` registry, and exclude `@appliedblockchain/*` from its cooldown (D6). A repository admin creates the Dependabot secret `GH_PACKAGES_READ_TOKEN` (classic token, `read:packages` only). Verify Dependabot's first update job for that workspace succeeds.
- [x] 2.15 Let `giano-ankr-key` match the Ankr WebSocket URL, which has `/ws/` before the key (D8). Verify with unit tests that `wss://rpc.ankr.com/eth/ws/<key>` matches and captures only the key, and that the URL without a key does not match.

## 3. Images (PR 3)

- [ ] 3.1 Change the `build` job of `docker.yml` as in D10: build to a tar, Trivy binary per architecture with recorded sha256, scan, report mode, then the existing push step only off PRs. Add Trivy to the pinning table. Verify all 16 build jobs are green on the PR.
- [ ] 3.2 Add the `diff_ids` comparison step after the push. Verify it with a `workflow_dispatch` run on the branch: the step passes and the logs show the cached build.
- [ ] 3.3 Triage the first scan results: fix by refreshing a DHI digest where a fix exists, or add a register entry. Verify every image scan passes.
- [x] 3.4 Update the ABIP-2 section of `docs/abip-compliance.md` with the scan step. Verify the doc matches the workflow.
- [x] 3.5 Add `.github/workflows/security-scan.yml` (Monday schedule and `workflow_dispatch`) as in the weekly-scan requirement: audit both workspaces, scan the `latest` tag of each of the 8 images, list entries expiring within 14 days, list dismissed CodeQL alerts without an entry. Least permissions per job (`packages: read`, `security-events: read`, `issues: write` on the report job only).
- [ ] 3.6 Make the report job open or update one issue labelled `security-scan`, and close it on a clean run. Verify with two `workflow_dispatch` runs: one with a test entry that expires within 14 days (issue opened), one without (issue closed).
- [x] 3.7 Pin the actions of the scan steps in `docker.yml` and of `security-scan.yml` to commit SHAs, as #246 does (D12). Verify `node scripts/check-ci-gate.mjs` passes.
- [x] 3.8 Say in `security/README.md` what to do when a new advisory fails every open PR: fix it in one PR, or add a short-lived entry with an owner and a `followUp`. Verify the README links resolve.

## 4. Reassess current advisories before the first production release (R4)

- [ ] 4.1 Re-run `pnpm audit` on both workspaces and compare with the open Dependabot alerts. For each open advisory, fix it if a patched version passes the regression gates and is at least 7 days old; otherwise add a register entry for it, or renew its entry with a new reason. Verify the audit output and the register agree.
- [ ] 4.2 Confirm `braces` and `sprintf-js`, recorded as residuals in the archived change `2026-10-26-fix-dependency-vulnerabilities`, are no longer reported, and say so in the PR description. Verify with the audit output.
- [ ] 4.3 Review every register entry with its owner and record the review date in the PR description. Verify no entry expires before the planned release date.

## Workflow follow-up

- Archive the change after every PR in the stack has merged.
