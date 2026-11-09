# Spec Delta

## MODIFIED Requirements

### Requirement: No unaddressed critical or high advisories
The resolved dependency tree of every workspace package SHALL contain no critical- or high-severity advisory unless that
advisory is recorded as an accepted residual. This covers the root workspace (the root, `packages/*`, `services/*` and
`e2e`, as locked in `pnpm-lock.yaml`) and the `services/custom-example` workspace (as locked in its own
`pnpm-lock.yaml`). Moderate and low advisories SHALL be fixed whenever a patched version passes the regression gates;
any left open SHALL also be recorded as accepted residuals. CI SHALL enforce the critical and high bar on every pull
request and before every release.

#### Scenario: Audit after remediation
- **WHEN** `pnpm audit` is run against the committed lockfile
- **THEN** every critical and high finding it reports appears in the accepted-residuals list, and the list is empty for
  critical and high unless a reason is given

#### Scenario: Audit in CI
- **WHEN** a pull request or a release runs CI
- **THEN** the dependency audit runs on both workspaces and fails on any critical or high advisory that is not an
  accepted residual

#### Scenario: Dependabot agrees with the audit
- **WHEN** the PR's branch is compared with the repository's open Dependabot alerts
- **THEN** every open critical or high alert on a workspace manifest or on `pnpm-lock.yaml` is either resolved by the
  PR or listed as an accepted residual

#### Scenario: Submodule lockfiles are not in scope
- **WHEN** an advisory is reported only against a lockfile inside a git submodule (`packages/contracts/lib/*`,
  `vendor/account-abstraction`)
- **THEN** it does not count against this bar, because those trees are pinned upstream sources, not installed
  dependencies

### Requirement: Accepted residuals are documented
Every advisory left open SHALL be recorded as an entry in the accepted-findings register (`ci-security-gates`). The
entry SHALL give the package, severity, advisory identifier, the workspace package(s) it reaches, and the reason it
stays open (no patch, patch breaks a gate with no fix in scope, no override path, or not reachable at runtime), plus a
suggested follow-up. It SHALL also name one owner and an expiry date, by which the owner reassesses the advisory.

#### Scenario: Residual without a reason
- **WHEN** the final report lists an open advisory without a reason
- **THEN** the change is not complete

#### Scenario: Residual without an owner or expiry
- **WHEN** an accepted residual has no owner or no expiry date
- **THEN** the register check fails CI and names the entry

#### Scenario: Residual recorded only in a change's tasks
- **WHEN** an open advisory is listed in an OpenSpec change's `tasks.md` but not in the register
- **THEN** it does not count as accepted
