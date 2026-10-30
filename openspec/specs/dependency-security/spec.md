# dependency-security Specification

## Purpose

Defines the security bar the pnpm workspace's resolved dependency tree must meet, and the rules for remediating
advisories without breaking the build, weakening the supply-chain cooldown, or silently moving contract addresses.

## Requirements

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
Both pnpm workspaces SHALL set `minimumReleaseAge` to at least **10080 minutes (7 days)**: the repository root and
`services/custom-example`. This is the ABIP-6 value for projects that handle financial transactions. The value SHALL
NOT be lowered. No package SHALL be exempt by name or by scope, `@appliedblockchain/*` included.

`minimumReleaseAgeExclude` MAY hold only version-specific entries (`name@x.y.z`). Such an entry is allowed only when a
critical security fix for a **direct** dependency must be consumed before its age window ends. Each entry SHALL be:
- added with a comment giving the advisory, the reason and the expected removal date;
- listed in the PR description;
- removed once that version is older than the minimum release age.

A CI check SHALL fail when either workspace has a value below 10080, a name-only or scope-wide exclusion, or a
version-specific exclusion whose version is already older than the window.

#### Scenario: A patched version is too new
- **WHEN** installing a patched version fails because it was published less than 7 days ago
- **THEN** either the bump waits, or, for a critical fix to a direct dependency, that exact version is excluded with a
  reason and a removal date; the cooldown value itself is unchanged

#### Scenario: Blanket exclusion rejected
- **WHEN** `minimumReleaseAgeExclude` contains `postcss` or `'@appliedblockchain/*'`
- **THEN** the release-age check fails CI and names the workspace file and the entry

#### Scenario: Stale exclusion rejected
- **WHEN** an excluded `name@x.y.z` was published more than 7 days ago
- **THEN** the release-age check fails CI and asks for the entry's removal

#### Scenario: Our own release is too new
- **WHEN** `services/custom-example` tries to install a giano-connector version published less than 7 days ago
- **THEN** the install is refused, and the example keeps its previous pinned version until the window passes

#### Scenario: Cooldown status is reported
- **WHEN** `docs/abip-compliance.md` is read
- **THEN** it states the configured minimum release age of each workspace and lists every active version-specific
  exclusion with its removal date

### Requirement: Dependency bumps preserve frozen addresses where the source allows
A dependency bump that would change the bytecode of a CREATE2-deployed contract SHALL first be checked for whether
the change reaching that contract is substantive. Where a contract compiles a dependency file whose only change is
non-functional, that file SHALL be pinned to its previous bytes, so the frozen address is kept. Where the change is
substantive, the bump SHALL be carried through as a new canonical freeze in the same change: the frozen constants,
generated ABIs, local devnet state and every document naming an affected address SHALL agree with a fresh
deterministic deployment. A live upgradeable proxy SHALL keep its address and be upgraded in place.

#### Scenario: Determinism check after the bump
- **WHEN** the contracts are recompiled with the canonical compiler settings and redeployed on a fresh local chain
- **THEN** every deployed CREATE2 address matches its committed canonical constant and every committed chain's
  registry entry

#### Scenario: Account addresses are preserved
- **WHEN** a passkey that resolved to a smart-account address before the change is resolved after it
- **THEN** it resolves to the same address, because the wallet factory and implementation keep their canonical
  addresses

#### Scenario: Existing paymaster proxies keep their funding address
- **WHEN** the paymaster's bytecode changes
- **THEN** the fresh-deployment constants are re-frozen, and existing proxies — the baked devnet's and any live
  chain's — are upgraded in place and keep their proxy address
### Requirement: Lockfiles are committed and installed frozen
Both lockfiles, `pnpm-lock.yaml` and `services/custom-example/pnpm-lock.yaml`, SHALL be committed. Every CI install
and every Dockerfile install SHALL use `--frozen-lockfile`. A lockfile change SHALL be its own commit, or its own PR,
together with the manifest change that caused it, so that a release-age or pin violation is visible in review.

#### Scenario: Unfrozen install introduced
- **WHEN** a workflow or Dockerfile runs `pnpm install` without `--frozen-lockfile`
- **THEN** the release-age check fails CI and names the file and line

#### Scenario: Lockfile churn hidden in a feature commit
- **WHEN** a commit changes application source and also `pnpm-lock.yaml` without a manifest change
- **THEN** it does not meet this requirement, and the lockfile change is moved into its own commit before review
