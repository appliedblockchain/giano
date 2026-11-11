# Proposal

## Why

CI has no security gate for dependencies, container images, application source, secrets or Solidity. Notion ticket G25
(Codex readiness report, finding 21) marks this as a pre-production blocker. Today a pull request can add a high
advisory, a leaked key or a vulnerable image layer, and nothing fails. `main` is protected, but it has no required status
checks, so even the existing checks do not block a merge.

G25 sets four requirements:
- **R1.** CI checks dependencies, images, source, secrets and Solidity.
- **R2.** Every accepted finding has a reason, an owner and an expiry date.
- **R3.** The checks gate releases and promotion.
- **R4.** Current advisories are reassessed before the first production release.

## What Changes

- **Accepted-findings register.** Add one register, `security/accepted-findings.json`. It holds every finding that a
  gate reports and the team accepts. Each entry has a reason, an owner and an expiry date. A dependency-free check
  script, with unit tests, validates the register and fails CI on a missing field or an expired entry. Every gate below
  reads the register. A tool-level suppression is allowed only if it names a register entry.
- **Solidity static analysis.** Add Slither and Aderyn to `ci.yml` for `packages/contracts/src`, with
  exact versions, a hash-locked pip requirements file for Slither, an Aderyn release binary checked against a
  recorded sha256, and both reports uploaded as artifacts. The job fails on any High finding that is not in the
  register. The four High findings from the trial run on 2026-11-09 go into the register with their reasons.
- **Dependency audit.** Run `pnpm audit` on both pnpm workspaces in `ci.yml`. It fails on a high or critical advisory
  that is not in the register. Extend `.github/dependabot.yml`, which #246 added for GitHub Actions, to npm (both workspaces), with a 7-day
  `cooldown` to match ABIP-6.
- **Source analysis.** Add a CodeQL workflow for JavaScript/TypeScript and GitHub Actions workflows.
- **Secret scanning.** Run gitleaks on the commits of each pull request.
- **Image scanning.** Run Trivy in `docker.yml` on every built image, after the build and before the push and signing.
  It fails on a High or Critical vulnerability that has a fix and is not in the register.
- **Weekly scan.** Add a scheduled workflow that re-runs the dependency audit and the image scan against the latest
  advisories, warns about register entries that expire soon, and reports the result in one GitHub issue.
- **Tool pinning rule.** Record in `docs/abip-compliance.md` that tools installed outside npm (pip packages, release
  binaries) follow ABIP-6 and ABIP-7 too: exact version, released at least 7 days earlier, with an integrity hash.
- **Accepted residuals gain owner and expiry.** The `dependency-security` rule for accepted residuals now requires an
  owner and an expiry date, and the residuals move into the register.

## Capabilities

### New Capabilities
- `ci-security-gates`: the security checks CI runs on every pull request and release, what makes each one fail, how an
  accepted finding is recorded and expires, and the weekly re-scan.

### Modified Capabilities
- `dependency-security`: the audit is enforced in CI on both workspaces, and accepted residuals are recorded in the
  register with an owner and an expiry date.

## Impact

- **Workflows.** `ci.yml` gains jobs for Solidity static analysis, the dependency audit, the secret scan and the
  register check. It also gains one summary job, "CI passed", that fails when any other `ci.yml` job fails. These run
  on every pull request and in the CI run that `release.yml` calls, so they also gate npm publishing. `docker.yml` gains an image scan before the push. New workflows: `codeql.yml` and `security-scan.yml`.
  Changed file: `.github/dependabot.yml`.
- **New files.** `security/accepted-findings.json`, `scripts/check-accepted-findings.mjs` and its test,
  `packages/contracts/slither.config.json`, `packages/contracts/aderyn.toml`,
  `packages/contracts/requirements-ci.in` and `requirements-ci.txt`, and `.gitleaks.toml`.
- **Contracts.** No contract source change. A Solidity comment would change the metadata hash in the bytecode and move
  the canonical CREATE2 addresses, so in-source suppressions are not used.
- **Docs.** `docs/abip-compliance.md` (tool pinning rule) and a short `security/README.md` on how to add an entry.
- **Out of scope.** G22 (independent contract review), G23 (deploys require CI success), G30 (rotate credentials in git
  history), G35 (sidecar images on moving tags), and a CI fuzz/invariant profile. #246 pinned the existing GitHub Actions
  to commit SHAs; this change pins the actions it adds and checks that every pin stays.
