# dependency-pinning Specification

## Purpose

Every dependency version Giano declares is an exact, reviewed choice. The manifests alone state what is built and
shipped, and no upgrade happens without a human editing a version. This is the repository's implementation of ABIP-7.

## Requirements

### Requirement: Every declared dependency is an exact version
Every entry in `dependencies`, `devDependencies` and `optionalDependencies` SHALL be an exact version (`MAJOR.MINOR.PATCH`,
with an optional pre-release suffix). This applies to every `package.json` in the repository: the root, `packages/*`,
`services/*` (including the separate `services/custom-example` workspace) and `e2e`.

The following SHALL NOT appear:
- range operators (`^`, `~`, `>=`, `<=`, `>`, `<`, `*`, `x`);
- dist-tags (`latest`, `next`, `beta`, `canary`);
- disjunctions (`||`).

`workspace:` and `catalog:` references are allowed. A git dependency SHALL be pinned to a 40-character commit SHA. A
tarball or `file:` dependency SHALL be pinned to an immutable content hash.

#### Scenario: Range rejected
- **WHEN** a PR changes `services/wallet-api/package.json` to `"fastify": "^5.12.1"`
- **THEN** the pinned-versions check fails CI and names the file, the field, the package and the specifier

#### Scenario: Workspace protocol accepted
- **WHEN** a package depends on `"@appliedblockchain/giano-wallet-core": "workspace:*"`
- **THEN** the check passes for that entry

### Requirement: Only published libraries keep peer-dependency ranges
The published `@appliedblockchain/*` libraries SHALL declare their `peerDependencies` as semver ranges. These are the
packages under `packages/*` that `release.yml` publishes: contracts, wallet-core, wallet-transport, wallet-kit,
connector, paymaster-sdk and tx-describe. In every other package, any `peerDependencies` SHALL be exact. In published
libraries too, every field other than `peerDependencies` SHALL be exact.

#### Scenario: Library peer range kept
- **WHEN** the check reads `packages/wallet-core/package.json` with `"peerDependencies": { "viem": "^2.31.0" }`
- **THEN** it passes for that entry

#### Scenario: Library devDependency must be exact
- **WHEN** `packages/connector/package.json` declares `"devDependencies": { "@rainbow-me/rainbowkit": "^2.2.4" }`
- **THEN** the check fails, because the exemption covers peer dependencies only

#### Scenario: A private package's peer range is rejected
- **WHEN** a private package (`"private": true`) declares a peer dependency range
- **THEN** the check fails

### Requirement: Override values are exact
Every value in the `overrides` map of both `pnpm-workspace.yaml` files SHALL be an exact version. This covers the root
workspace and `services/custom-example`. An override's selector key MAY keep the version range that scopes which
resolutions it replaces, such as `"undici@>=5.0.0 <6.28.0"`.

#### Scenario: Security floor pinned
- **WHEN** the check reads the override `"ws@>=8.0.0 <8.21.0": "8.21.0"`
- **THEN** it passes

#### Scenario: Caret override rejected
- **WHEN** an override value reads `"^8.21.0"`
- **THEN** the check fails and names the override key

### Requirement: The range check runs in CI on every pull request
A dependency-free repository check SHALL scan every manifest and both override maps. It SHALL run in `ci.yml` on every
pull request, including PRs into `main` and `production`, and in the CI run that `release.yml` calls before publishing. It SHALL have its own unit tests, covering each accepted and
rejected specifier form. Transitive ranges inside dependencies are out of scope, because the lockfile pins them.

#### Scenario: Check on a clean tree
- **WHEN** the check runs on the tree after this change
- **THEN** it reports zero violations and exits 0

### Requirement: Pinning does not change what is resolved beyond the pin itself
Each range SHALL be replaced with an exact version that satisfies it and passes the workspace's minimum release age.
The lockfile SHALL be regenerated in the same PR, and that PR SHALL contain no unrelated functional change. CREATE2 and
CREATE3 canonical addresses and the committed release bytecode SHALL NOT change.

#### Scenario: Determinism preserved
- **WHEN** the determinism and release-verify checks run after pinning
- **THEN** every canonical address and every committed release reproduces unchanged

#### Scenario: Frozen install
- **WHEN** `pnpm install --frozen-lockfile` runs in each workspace on the pinned tree
- **THEN** it succeeds without modifying the lockfile

### Requirement: Upgrades are deliberate, reviewed and isolated
A dependency upgrade SHALL edit the pinned version in the manifest and commit the resulting lockfile change in the
same PR. It SHALL go through code review, and SHALL NOT be combined with unrelated functional changes. Grouping related
packages in one upgrade PR is allowed.

#### Scenario: Upgrade mixed with a feature
- **WHEN** a PR bumps `viem` and also changes wallet-api route behaviour
- **THEN** it does not meet this requirement and is split before review
