# Spec Delta

## Purpose

Defines the security checks that CI runs on every pull request, release and published image, what makes each check
fail, and how the team records, owns and expires a finding it accepts. This is the repository's answer to G25.

## ADDED Requirements

### Requirement: One register holds every accepted finding
Every finding that a security check reports and the team accepts SHALL be recorded in one register file in the
repository. A finding that is not in the register SHALL count as open. No check SHALL accept a finding that is recorded
anywhere else.

#### Scenario: Finding accepted in the register
- **WHEN** a check reports a finding whose identifier matches a valid register entry for the same tool
- **THEN** the check does not fail on that finding, and its log names the register entry

#### Scenario: Finding accepted only in a PR description
- **WHEN** a finding is explained in a PR description but has no register entry
- **THEN** the check fails on that finding

### Requirement: Every register entry has a reason, an owner and an expiry date
Each register entry SHALL give a unique entry ID, the tool, the tool's identifier for the finding, its severity, the
date it was accepted, a reason, one named owner and an expiry date. The expiry date SHALL be no more than 180 days after
the accepted date. The register check SHALL fail on a missing field, a duplicate ID or an expiry beyond that limit.

#### Scenario: Entry without an owner
- **WHEN** a register entry has an empty `owner`
- **THEN** the register check fails and names the entry ID and the missing field

#### Scenario: Expiry too far ahead
- **WHEN** an entry accepted on 2026-11-09 has an expiry of 2027-12-01
- **THEN** the register check fails, because the expiry is more than 180 days after acceptance

### Requirement: An expired entry fails CI
An entry whose expiry date has passed SHALL fail the register check on every pull request and every release until the
entry is renewed with a new reason and date, or removed.

#### Scenario: Expiry passes
- **WHEN** CI runs on a date after an entry's expiry date
- **THEN** the register check fails and names the entry, its owner and its expiry date

#### Scenario: Renewal
- **WHEN** the owner reassesses an expired entry and sets a new accepted date, reason and expiry
- **THEN** the register check passes again

### Requirement: Tool-level suppressions name a register entry
A suppression in a security tool's configuration SHALL name the register entry that justifies it. A suppression in
Solidity source SHALL NOT be used, because a source comment changes the contract bytecode. Path filters that define a
tool's scope are not suppressions, but each SHALL carry a reason.

#### Scenario: Suppression without an entry
- **WHEN** a gitleaks allowlist block has no register entry ID in its description
- **THEN** the register check fails and names the file and the block

#### Scenario: In-source Solidity suppression
- **WHEN** a file under `packages/contracts/src` contains a `slither-disable` or `aderyn-ignore` comment
- **THEN** the register check fails and names the file and line

### Requirement: Solidity static analysis fails on High findings
On every pull request, Slither and Aderyn SHALL analyse the production contracts in `packages/contracts/src`, excluding
`src/testing`, test code and dependencies. The check SHALL fail on any High finding from either tool that is not in the
register. It SHALL also fail on any register entry of either tool that matches no finding in the report. Both full
reports SHALL be kept as CI artifacts, also when the check fails.

#### Scenario: New High finding
- **WHEN** a PR adds a contract change that Slither reports as High
- **THEN** the Solidity analysis check fails and names the detector, file and line

#### Scenario: Medium finding
- **WHEN** Aderyn or Slither reports only Medium, Low or Informational findings
- **THEN** the check passes, and the findings appear in the uploaded reports

#### Scenario: Reports kept on failure
- **WHEN** the check fails
- **THEN** the Slither and Aderyn reports are still uploaded

#### Scenario: Finding fixed but entry kept
- **WHEN** a PR fixes a finding that has a Slither or Aderyn register entry, and does not remove the entry
- **THEN** the check fails and names the entry that matches no finding

### Requirement: Dependency audit fails on high or critical advisories
On every pull request, the dependency audit SHALL check the lockfile of each pnpm workspace (the root and
`services/custom-example`) against the current advisory database. It SHALL fail on a high or critical advisory that is
not in the register for that workspace. It SHALL fail when it cannot obtain the audit result.

#### Scenario: New high advisory
- **WHEN** a high advisory is published for a package in `pnpm-lock.yaml` and has no register entry
- **THEN** the dependency audit fails on every PR and names the package, the advisory ID and the workspace

#### Scenario: Registry unreachable
- **WHEN** the advisory request fails or returns no valid result
- **THEN** the dependency audit fails and says that it could not audit, rather than passing

### Requirement: Dependency updates respect the release-age window
Automated dependency update PRs SHALL be configured for npm in both workspaces and for GitHub Actions. Version
update PRs SHALL NOT propose a version published less than 7 days earlier.

#### Scenario: New npm release
- **WHEN** a dependency publishes a new version
- **THEN** no version update PR proposes it until 7 days after its release

### Requirement: Source analysis covers TypeScript and workflows
On every pull request and on `main`, CodeQL SHALL analyse the JavaScript/TypeScript code and the GitHub Actions
workflows. A dismissed CodeQL alert SHALL have a register entry.

#### Scenario: New alert in a PR
- **WHEN** a PR introduces code that CodeQL reports as a high or critical security alert
- **THEN** the code scanning check on the PR fails

#### Scenario: Dismissal without an entry
- **WHEN** the weekly scan finds a dismissed CodeQL alert with no register entry
- **THEN** the weekly scan reports it as an open finding

### Requirement: Secret scan covers every pull request's commits
On every pull request, a secret scanner SHALL scan every commit the PR adds. It SHALL fail on any detected secret that
is not in the register or in an allowlist that names a register entry. The scan SHALL need no repository secret, so it
runs on fork PRs too.

#### Scenario: Key committed in a PR
- **WHEN** a PR commit adds a string that matches a private-key rule
- **THEN** the secret scan fails and names the commit, file and rule, without printing the full secret

#### Scenario: Public test key
- **WHEN** a PR adds one of the well-known Anvil development keys
- **THEN** the scan passes, because an allowlist that names a register entry covers those keys

### Requirement: Images are scanned before they are published
Every image that `docker.yml` builds SHALL be scanned for vulnerabilities on each architecture before it is pushed or
signed. The scan SHALL fail on a High or Critical vulnerability that has a fixed version and is not in the register. A
failed scan SHALL leave nothing pushed, tagged or signed for that image.

#### Scenario: Vulnerable package with a fix
- **WHEN** a built image contains a package with a Critical vulnerability that has a fixed version
- **THEN** the image job fails before the push, and no digest for it reaches GHCR or ECR

#### Scenario: Vulnerability with no fix
- **WHEN** a High vulnerability has no fixed version
- **THEN** the scan does not fail on it, and the report lists it

### Requirement: Security checks gate releases and promotion
Every security check that runs on pull requests SHALL run on pull requests into `main` and into `production`, and in
the CI run that the release workflow calls before it publishes packages. The image scan SHALL gate image publishing.
Each security check SHALL report a stable check name on every pull request, with no path filter. `ci.yml` SHALL report
one summary check that fails when any of its jobs fails.

#### Scenario: Release with an open finding
- **WHEN** a release runs while the dependency audit or the register check fails
- **THEN** the release does not publish any package

#### Scenario: One CI job fails
- **WHEN** any job in `ci.yml` fails, is cancelled or is skipped
- **THEN** the summary check fails too

#### Scenario: Promotion PR
- **WHEN** a PR from `main` into `production` is opened
- **THEN** every security check runs on it and reports the same check names as on a PR into `main`

### Requirement: A weekly scan re-checks published state
A scheduled workflow SHALL run at least once a week. It SHALL re-run the dependency audit on both workspaces, scan the
latest published image of each repository image, list register entries that expire within 14 days, and report
dismissed CodeQL alerts without a register entry. It SHALL report its result in one tracking issue.

#### Scenario: New advisory between PRs
- **WHEN** a critical advisory is published for an image's package and no PR runs that week
- **THEN** the weekly scan opens or updates the tracking issue and names the image and the advisory

#### Scenario: Entry close to expiry
- **WHEN** a register entry expires in 10 days
- **THEN** the weekly scan lists it in the tracking issue with its owner

#### Scenario: Clean week
- **WHEN** the weekly scan finds nothing open and nothing close to expiry
- **THEN** it closes the tracking issue if one is open

### Requirement: Security tools are pinned
Every security tool that CI installs SHALL be an exact version released at least 7 days before it is adopted. A tool
installed outside npm SHALL be verified by an integrity hash: pip packages by a hash-locked requirements file, and
release binaries by a sha256 recorded in the workflow. A hash mismatch SHALL fail the job before the tool runs.

#### Scenario: Binary tampered with
- **WHEN** the downloaded Aderyn, gitleaks or Trivy archive does not match its recorded sha256
- **THEN** the job fails before the tool runs

#### Scenario: Floating version
- **WHEN** a workflow installs a security tool as `latest` or without a version
- **THEN** the change does not meet this requirement and is not merged

### Requirement: Workflow actions stay pinned
Every action and reusable workflow that a workflow in `.github/workflows` uses SHALL be a local path or SHALL be
pinned to a full commit SHA. A container image SHALL be pinned by digest. The same rules SHALL apply to the actions
that a local action uses, and a local Docker action SHALL use a `docker://` image pinned by digest, not a Dockerfile.
The CI summary check SHALL fail on any other reference.

#### Scenario: Action moved back to a tag
- **WHEN** a PR changes a workflow step to `uses: actions/checkout@v7`
- **THEN** the CI gate check fails, and so does the summary check

#### Scenario: Job container on a tag
- **WHEN** a PR adds `container: node:24` or a service with `image: postgres:17` to a job
- **THEN** the CI gate check fails, and so does the summary check

#### Scenario: Local Docker action on a tag
- **WHEN** a PR adds a local Docker action with `image: docker://alpine:3.20` or `image: Dockerfile`
- **THEN** the CI gate check fails, and so does the summary check
