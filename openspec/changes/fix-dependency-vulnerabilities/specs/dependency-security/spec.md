## Purpose

Defines the security bar the pnpm workspace's resolved dependency tree must meet, and the rules for remediating
advisories without breaking the build, weakening the supply-chain cooldown, or silently moving contract addresses.

## ADDED Requirements

### Requirement: No unaddressed critical or high advisories
The resolved dependency tree of every workspace package (the root, `packages/*`, `services/*` and `e2e`, as locked in
`pnpm-lock.yaml`) SHALL contain no critical- or high-severity advisory unless that advisory is recorded as an accepted
residual. Moderate and low advisories SHALL be fixed whenever a patched version passes the regression gates; any left
open SHALL also be recorded as accepted residuals.

#### Scenario: Audit after remediation
- **WHEN** `pnpm audit` is run against the committed lockfile
- **THEN** every critical and high finding it reports appears in the accepted-residuals list, and the list is empty for
  critical and high unless a reason is given

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
Every advisory left open SHALL be recorded with its package, severity, advisory identifier, the workspace package(s)
it reaches, and the reason it stays open (no patch, patch breaks a gate with no fix in scope, no override path, or not
reachable at runtime), plus a suggested follow-up.

#### Scenario: Residual without a reason
- **WHEN** the final report lists an open advisory without a reason
- **THEN** the change is not complete

### Requirement: Remediation is gated by severity level
Advisories SHALL be fixed in ascending severity order (low, moderate, high, critical). After each level the lockfile
SHALL be regenerated and the per-level regression gates SHALL pass before work on the next level starts. The per-level
gates are the builds, tests, type checks, lint and ABI-drift check that CI runs for the workspace packages, plus the
Foundry test suite. The CREATE2 determinism check SHALL also pass after any level that changes contract bytecode, and
the end-to-end suite SHALL pass once on the final tree before the PR is opened.

#### Scenario: A gate fails mid-level
- **WHEN** a gate fails after bumping the packages of one severity level
- **THEN** the next severity level is not started until the offending bump is fixed, replaced by a compatible patched
  version, or moved to the accepted residuals with a reason

#### Scenario: The lockfile is in sync
- **WHEN** `pnpm install --frozen-lockfile` runs on the merged branch
- **THEN** it succeeds without modifying `pnpm-lock.yaml`

### Requirement: The release-age cooldown is preserved
The workspace's minimum release age (currently 1440 minutes) SHALL NOT be lowered or removed by this remediation. A
fixed version younger than the cooldown SHALL either be waited out or be added to the cooldown's exclusion list by name,
each such exclusion decided per package and listed in the final report.

#### Scenario: A patched version is too new
- **WHEN** installing a patched version fails because it was published less than 24 hours ago
- **THEN** either the bump waits, or the package is excluded by name and the exclusion is reported — the cooldown value
  itself is unchanged

#### Scenario: Cooldown status is reported
- **WHEN** the final report is written
- **THEN** it states whether a minimum release age is configured and names every package excluded from it

### Requirement: Address-moving bumps produce a new canonical freeze
A dependency bump that changes the bytecode of a CREATE2-deployed contract SHALL be carried through as a new canonical
freeze in the same change: the frozen canonical constants, the contracts address registry, the generated ABIs, the local
devnet state and every configuration that names an affected address SHALL all agree with a fresh deterministic
deployment. The smart-account factory and implementation addresses SHALL NOT change as a side effect of such a bump.

#### Scenario: Determinism check after the bump
- **WHEN** the contracts are recompiled with the canonical compiler settings and redeployed on a fresh local chain
- **THEN** every deployed CREATE2 address matches its committed canonical constant and registry entry

#### Scenario: User account addresses are stable
- **WHEN** a passkey that resolved to a smart-account address before the change is resolved after it
- **THEN** it resolves to the same address

#### Scenario: A committed chain goes stale
- **WHEN** a committed chain's registry entry names a contract whose canonical address moved
- **THEN** the final report lists that chain and contract as needing an operator redeploy
