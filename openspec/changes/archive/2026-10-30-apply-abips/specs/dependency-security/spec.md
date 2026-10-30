## MODIFIED Requirements

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

## ADDED Requirements

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
