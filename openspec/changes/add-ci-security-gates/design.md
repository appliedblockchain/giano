# Design

## Context

See `proposal.md` for the motivation. The current state that shapes the design:

- **Workflows.** `ci.yml` runs on `pull_request` and `workflow_call`. `release.yml` calls it and publishes only when it
  passes (`needs: [ci, determinism]`). `docker.yml` builds 8 images on 2 native architectures. On `main` and `v*` tags
  the build step pushes each image by digest to GHCR. The `merge` job then tags, copies to ECR and signs with cosign.
  Since #246, every third-party action is pinned to a full commit SHA, and `.github/dependabot.yml` keeps the pins
  current.
- **Existing policy checks.** `scripts/check-dockerfiles.mjs`, `check-release-age.mjs` and `check-pinned-versions.mjs`
  are dependency-free Node scripts with `node --test` unit tests. Each has its own CI job.
- **GitHub state on 2026-11-09.** The repository is public. Dependabot alerts are on, with 2 open medium alerts
  (`minimatch` GHSA-g3hv-75wg-m249, `glob` GHSA-3g3m-2fjr-6pw4). There is no `.github/dependabot.yml` and no code
  scanning. `main` is protected, but its required status checks list is empty. Repository settings are handled
  outside this change.
- **Current audit.** `pnpm audit` reports 0 high or critical advisories in both workspaces, and the 2 moderate ones
  above. The residuals that the archived change `2026-10-26-fix-dependency-vulnerabilities` recorded (`braces`,
  `sprintf-js`) are no longer reported. #260 later fixed both moderate advisories by lifting `glob` to 14.0.3,
  which brings `minimatch` 11.0.4. Since then `pnpm audit` reports none in the root workspace.
- **Trial run of Slither and Aderyn (2026-11-09).** Slither 0.11.6 reported 1 High, 2 Medium, 6 Low and 18
  Informational. Aderyn v0.6.8 reported 3 High detectors (4 instances) and 15 Low detectors. All Highs look like false
  positives or deliberate design (table in D9). Slither's Foundry integration runs `forge clean`, which deletes `out/`.
- **Frozen addresses.** solc embeds a hash of every source file in the contract metadata. A comment added to a `.sol`
  file changes the bytecode and the CREATE2 addresses (`dependency-security`, frozen addresses requirement).

## Goals / Non-Goals

**Goals:**
- One place, one format and one check for every accepted finding, whatever the tool.
- Every gate fails closed: a tool that cannot produce a result fails the job.
- The gates need no repository secret, so they run on fork PRs.
- Each new job reports a stable check name on every PR, so it can be used as a required check.

**Non-Goals:**
- Gating deploys on CI (G23). This design gates merge, npm release, image publishing and promotion only.
- Fixing the findings themselves, beyond recording them in the register.
- Pinning the existing Actions to commit SHAs. #246 did that for every workflow. This change pins the actions that its
  own jobs add, and the CI gate check keeps every pin in place (D12).
- Changing any contract source.

## Decisions

### D1. The register is one JSON file: `security/accepted-findings.json`

The existing policy scripts have no dependencies. A YAML register would need a YAML parser or a fragile hand parser.
JSON has neither problem, and Biome already formats it. The cost is no comments, but the `reason` field holds the
explanation. `security/README.md` explains how to add an entry.

Entry shape:

```json
{
  "id": "AF-001",
  "tool": "slither",
  "match": { "check": "arbitrary-send-eth", "id": "73b125f9973ab839…" },
  "severity": "high",
  "location": "packages/contracts/src/GianoSmartWallet.sol#L299-L306",
  "accepted": "2026-11-09",
  "expires": "2027-05-08",
  "owner": "Sarah Thompson",
  "reason": "…",
  "followUp": "…"
}
```

- `id` is `AF-` and three digits, unique, never reused.
- `owner` names one person, not a team.
- `expires` is at most 180 days after `accepted`. 180 days is long enough for a confirmed false positive and short
  enough that a person looks at it twice a year. An entry that only unblocks CI until a fix lands uses a shorter date.
- `followUp` is optional.

Alternative considered: per-tool ignore files (`.trivyignore`, `.gitleaksignore`, Slither's triage database, pnpm's
`auditConfig.ignoreGhsas`). They have different formats, and most cannot hold an owner or an expiry. R2 would need a
second check for each one.

### D2. Tools run without suppressions; one script decides

Each tool writes a full JSON report. `scripts/check-accepted-findings.mjs` then reads the report and the register and
decides pass or fail. The script has two modes:

- **Register mode** (no arguments): validates the register (fields, dates, expiry, duplicate IDs). It also checks that
  every suppression in a tool config file names a register entry, and that no file under `packages/contracts/src`
  contains a `slither-disable` or `aderyn-ignore` comment.
- **Report mode** (`--tool <tool> --report <file> […]`): reads one report, keeps findings at or above the gate
  severity, drops the ones that match a valid (not expired) register entry, and fails on the rest. It fails when the
  report is missing or not valid JSON. It prints each accepted finding with its entry ID. For `slither` and `aderyn`,
  it also fails on each entry of that tool that matches no finding in the report. Their findings change only with the
  contract source or the pinned tool version, so an unused entry means the finding was fixed or moved, and the same PR
  removes or updates the entry. The other tools' findings can change without a code change, for example when an
  advisory database changes, so their unused entries do not fail.

Match keys:

| Tool | Gate | Match key |
|------|------|-----------|
| `slither` | High | `check` and the result `id`. Slither derives the `id` from the flagged code, so it changes when the code changes, and the entry must be reviewed again. |
| `aderyn` | High | detector name, `contract_path` and `line_no`. Aderyn has no stable finding hash. A line shift above the finding needs an entry update; that is an accepted cost. |
| `pnpm-audit` | high, critical | workspace and GHSA ID |
| `trivy` | HIGH, CRITICAL with a fix | image name, package name and vulnerability ID |
| `gitleaks` | any | finding fingerprint |
| `codeql` | (checked weekly) | rule ID and alert number |

Alternative considered: `slither --fail-high` with Slither's triage database. It works for Slither only,
and the database cannot hold an owner or an expiry.

### D3. No in-source suppression in Solidity

A `// slither-disable-next-line` comment changes the metadata hash, and so the canonical CREATE2 addresses of the
wallet factory, implementation and paymaster. The register check rejects these comments and symlinks under
`packages/contracts/src`, and `src` itself as a symlink. Slither also runs with `show_ignored_findings` and an explicit
`--config-file`, so it ignores `slither-disable` comments and triage files in every file, including dependencies, and
never falls back to `slither.conf.json`.

Tool configs hold only the scope: production contracts in `packages/contracts/src` without `src/testing/`, which holds
test-only contracts (`PermissivePaymaster`, `PrivateERC20`) that production never deploys. Slither uses `include_paths`,
which keeps a finding when any of its code is in that scope; `filter_paths` would drop a finding in `src/` that also
touches `lib/`. The script does not read what the configs set. It compares each file with a fixed copy, apart from
the reasons: `slither.config.json` must be exactly the fixed object plus a `//` member, and `aderyn.toml` exactly the
fixed lines plus blank lines and whole-line comments. It fails if either file is missing. So a scope change is a
change to the script, and no JSON or TOML form can add a setting that the check does not see.
Slither keeps its informational and optimization detectors off. Severity filters are not suppressions.

### D4. Solidity analysis is its own job in `ci.yml`

Job `solidity-analysis`, named "Solidity static analysis (Slither, Aderyn)". It is separate from `forge` and
`forge-coverage`, because Slither runs `forge clean` and rebuilds with `--build-info`.

- Checkout with submodules. Foundry v1.7.1 through `foundry-toolchain`, as the other jobs use.
- Python 3.12 through `actions/setup-python`. `pip install --require-hashes -r packages/contracts/requirements-ci.txt`.
  `requirements-ci.in` pins `slither-analyzer==0.11.6` (the trial version). `requirements-ci.txt` is generated with
  `uv pip compile requirements-ci.in --python-version 3.12 --universal --generate-hashes`.
- Aderyn v0.6.8 Linux x86_64 release archive, checked with `sha256sum -c` against the sha256 recorded in the workflow.
- Config files in `packages/contracts`: `slither.config.json` (`include_paths`, `show_ignored_findings`, informational
  and optimization off) and `aderyn.toml` (source root `src`, exclude `src/testing`).
- Each tool step deletes its old report first: Slither keeps an existing report file instead of overwriting it.
- Run both tools with `if: ${{ !cancelled() }}` on the second, so one failure does not hide the other report. Then
  run the script in report mode for each report. Upload `slither.json`, `slither.sarif` and `aderyn-report.json` with
  `if: always()`.

### D5. Dependency audit: `pnpm audit --json`, fail closed

Job `dependency-audit`, named "Dependency audit (pnpm audit)". It needs only pnpm, not an install. For each workspace:
`pnpm audit --json > audit-<workspace>.json`, then the script in report mode. `pnpm audit` exits non-zero when it
finds any advisory, so the job ignores that exit code and relies on the script. The script fails when the JSON is
missing, empty or carries an error object, so a registry outage fails the job instead of passing it. The command
line sets `--registry` and clears `https-proxy` and `proxy`, which override every config file. So a PR cannot send
the audit to another server, or through a proxy that answers for the registry.

### D6. Dependabot configuration

`.github/dependabot.yml` holds three entries: npm at `/`, npm at `/services/custom-example`, and `github-actions` at
`/`. #246 added the file with the `github-actions` entry, so PR 2 adds only the two npm entries. All are weekly with
`cooldown: default-days: 7`. The `services/custom-example` entry excludes `@appliedblockchain/*` from the cooldown,
as its `pnpm-workspace.yaml` excludes it from `minimumReleaseAge` (the recorded ABIP-6 deviation). It reads that scope
from GitHub Packages through a `registries` entry with the Dependabot secret `GH_PACKAGES_READ_TOKEN`, because GitHub
Packages refuses anonymous reads. npm uses `versioning-strategy: increase-if-necessary`: an exact pin always changes,
so pins stay exact (ABIP-7), and a `peerDependencies` range of a published package that already accepts the new
release stays as it is. Each npm entry has an open PR limit of 5 and the commit prefix `chore` with the scope.
Dependabot puts the manifest and lockfile change in one PR, as `AGENTS.md` requires. Every entry ignores semver-major updates, so a major upgrade is done by hand and gets its own
review. For actions, some must also change major version together (#246). The ignore may also stop a security
update PR that needs a new major version. The Dependabot alert and the dependency audit still report that advisory.
Dependabot cannot exempt one scope from the `*` ignore, so a new major of `@appliedblockchain/*` in the example is
also installed by hand.

Security update PRs ignore `cooldown`. A security PR that proposes a version younger than 7 days fails the
`release-age-policy` job. It then waits, as ABIP-6 says. This needs no new rule.

The pip requirements file and the release binaries are not covered by Dependabot. They are updated by hand under the
pinning rule (D11).

### D7. CodeQL as an advanced-setup workflow

`.github/workflows/codeql.yml` runs on `pull_request`, on push to `main` and weekly. It uses a matrix of
`javascript-typescript` and `actions`, with `build-mode: none`, and `permissions: security-events: write` on the
analyse job only. A workflow file is reviewed like any other code, unlike CodeQL's default setup, which lives in the
repository settings.

On a PR, GitHub adds a "CodeQL" check that fails on new alerts at the configured severity (high and critical security
alerts). That check is the gate. CodeQL does not support Solidity, so D4 covers the
contracts.

CodeQL alerts are dismissed in the GitHub UI, outside the repository. The weekly scan lists dismissed alerts through
the API and reports any without a register entry (tool `codeql`). This keeps R2 for CodeQL too.

### D8. gitleaks as a pinned binary on the PR commit range

Job `secret-scan`, named "Secret scan (gitleaks)". It uses the gitleaks release binary with a recorded sha256. The
gitleaks GitHub Action needs a paid licence for organisation repositories, and a binary follows the same pattern as
Aderyn.

- On `pull_request`: checkout with full history, then `gitleaks git --log-opts="<base sha>..<head sha>" --redact
  --ignore-gitleaks-allow --report-format json --exit-code 0`. `--ignore-gitleaks-allow` makes gitleaks ignore
  `gitleaks:allow` comments, which would hide a secret without a register entry. The script then decides, in report
  mode.
- On `workflow_call` (the release run): every commit on `main` arrived through a PR that ran the scan, so the job
  checks the register only and passes. It still reports the same check name.
- `.gitleaks.toml` extends the default rules. One allowlist covers the public Anvil
  development keys that the devnet and tests use (AF-008). A second covers Ethereum addresses (AF-009), which
  `generic-api-key` flags under key names such as `defaultToken`. A third covers the one public Infura key that
  forge-std ships in `StdChains.sol` and that the release `standard-input.json` files embed (AF-010). Each allowlist
  description starts with its register entry ID. An
  allowlist holds only `description` and `regexes`, so it matches the secret only. The register check does not read
  the regexes: a PR can widen an allowlist without changing its entry. Code-owner review of `.gitleaks.toml` covers
  that. It needs a `.github/CODEOWNERS` file, which the repository does not have yet.
- The default rules do not detect a provider key in an RPC URL, the one kind of secret this repository has leaked
  (#244). `.gitleaks.toml` adds four rules for them: `giano-infura-key`, `giano-alchemy-key`, `giano-quicknode-key`
  and `giano-ankr-key`. Each rule matches the HTTPS and WebSocket URLs of its provider, and captures only the key,
  so `--redact` hides it. A custom rule with the ID of a default rule replaces that rule, so the register check
  accepts a `[[rules]]` table only when its `id` starts with `giano-`, and only with `id`, `description`, `regex` and
  `keywords`. A custom rule can therefore only add detection.
- The commit range uses `--diff-merges=remerge`. By default `git log` shows no diff for a merge commit, so a secret
  added while resolving a merge would not be scanned. It also uses `--text --no-textconv`, so a `.gitattributes` line
  that marks a file as binary cannot hide its content. gitleaks logs a git or diff parse error and goes on, so a range
  or option git rejects scans 0 commits and passes, and a commit it cannot parse is skipped. The job therefore checks
  the range with `git rev-list` and fails on any error line in the gitleaks log. It also runs `git log` with the same
  options and counts the commits that add a line. gitleaks counts every commit with a text hunk in a file that is not
  deleted, so the job fails if gitleaks reports fewer scanned commits than that. Empty commits and clean merges add no
  line, so they are not counted.

Scanning the full history is out of scope. Credentials already in history are G30.

### D9. Initial register content

| ID | Tool | Finding | Assessment |
|----|------|---------|------------|
| AF-001 | slither | `arbitrary-send-eth`, `GianoSmartWallet._call` (L299-306) | False positive. `execute` and `executeBatch` are `onlyEntryPointOrOwner` (the EntryPoint, an owner or the account itself). `executeWithoutChainIdValidation` is `onlyEntryPoint` and calls only `address(this)`. The Slither id includes the line of the call, so an edit above it changes the id. |
| AF-002 | aderyn | `contract-locks-ether`, `GianoSmartWalletFactory.sol:14` | False positive. `createAccount` is payable and forwards `msg.value` to the account through Solady `LibClone`, in inline assembly where Aderyn does not count sends. Aderyn skips constructors in this check, so `createAccount` alone triggers it. The `payable` constructor (L36) receives no ether: the deploy CLI calls CreateX `deployCreate3` without value. |
| AF-003 | aderyn | `contract-locks-ether`, `GianoPaymaster.sol:50` | False positive. `receive()` reverts, and `depositFor` and `addStake` (L553) forward all of `msg.value` to the EntryPoint. The inherited `upgradeToAndCall` is also payable, but only `UPGRADER_ROLE` can call it, through the proxy, and the implementation it chooses handles the value. Aderyn 0.6.8 does not count a call with value to a named function as a send. |
| AF-004 | aderyn | `unprotected-initializer`, `GianoSmartWalletFactory.sol:81` | False positive. The flagged function is the view `initCodeHash()`. Aderyn matches the `init` name prefix and finds no revert or `initializer` modifier; it does not check mutability. |
| AF-005 | aderyn | `yul-return`, `ERC1271InputGenerator.sol:48` | By design. The constructor returns the replay-safe hash to an `eth_call`; no deploy script or release deploys the contract, and no code in this repo calls it. It fails for hashes that start with byte `0xEF` (EIP-3541), a point for G22. |

Rui Sereno owns every initial entry. The register first also held AF-006 and AF-007 for the `minimatch` and `glob`
advisories. #260 fixed both, so the entries were removed. Their IDs are not reused. G22 (independent contract
review) is the follow-up for the contract entries. The 2 Slither Mediums (`unused-return` in `registerTenant` and
`validatePaymasterUserOp`) are below the gate. Both are safe, and they stay visible in the uploaded report.

### D10. Trivy in `docker.yml`, before the push

Trivy runs as a pinned release binary with a recorded sha256, one per runner architecture. The `build` job holds
`packages: write` and, at workflow level, `id-token: write`. A binary with a known hash runs no third-party action code
with those permissions.

Each `build` matrix job changes to:

1. **Build for the scan.** `docker/build-push-action` with `outputs: type=docker,dest=$RUNNER_TEMP/image.tar`, no
   push, and no SBOM or provenance. It reads the same GHA cache scope as today.
2. **Scan.** `trivy image --input $RUNNER_TEMP/image.tar --scanners vuln --pkg-types os,library --config ""
   --ignorefile "" --format json`, in an empty directory, then the script in report mode with `--image <name>`. A
   failure stops the job here. Trivy runs with no severity filter and without `--ignore-unfixed`, so the report holds
   every finding and the script applies the gate (HIGH or CRITICAL with a fixed version). `--config ""` and
   `--ignorefile ""` stop Trivy from reading `trivy.yaml` or `.trivyignore`, and the step fails if any `TRIVY_`
   environment variable is set. The script also fails on a report in which Trivy detected no OS, or an OS it marks as
   end of life: either report would be valid but pass every OS finding.
3. **Build and push.** The existing step, unchanged, now only when not a pull request. The builder still holds every
   layer from step 1, so this step rebuilds nothing. It adds SBOM and provenance and pushes by digest.
4. **Confirm what was pushed is what was scanned.** Compare the layer `diff_ids` of the pushed digest with those of
   `/tmp/image.tar`, and fail on any difference. The `merge` job, which tags and signs, needs `build`, so it does not
   run.

On a pull request the job runs steps 1 and 2 only. Step 1 still exercises every Dockerfile on both architectures,
which is why PRs build images today.

Alternative considered: scan the digest after the push-by-digest step, before `merge`. It is simpler, but the untagged
digest is already pullable from GHCR when the scan fails.

Trivy downloads its vulnerability database on each run. The jobs list fallback mirrors (`--db-repository` with
`mirror.gcr.io`, then the public ECR mirror, then GHCR) to reduce rate-limit failures. A failed download fails the job.
It never skips the scan.

The weekly scan (`security-scan.yml`) runs the same Trivy options on the `latest` tag of each image, for both arches,
from an amd64 runner. It reads the image list from `docker.yml`, as `scripts/check-dockerfiles.mjs` does, and fails if
the number of images it reads differs from the number of Dockerfiles listed.

### D11. Pinning rule for tools outside npm

Recorded in `docs/abip-compliance.md` under ABIP-6 and ABIP-7. The rule: an exact version, released at least 7 days
before the PR that adopts it, with an integrity hash. pip packages use a hash-locked requirements file. Release
binaries use a sha256 in the workflow's `env`, next to the version and a comment with the release date. Trial versions:
Slither 0.11.6 and Aderyn v0.6.8. gitleaks and Trivy versions are chosen when their PRs are written, under the same
rule. The rule is not checked automatically; a check of binary release dates would need network access to each
project's release page.

### D12. One summary check for `ci.yml`

GitHub has no "every job must pass" setting. Branch protection and rulesets accept only a list of check names. So
`ci.yml` gets a last job, `ci-passed` ("CI passed"). It `needs` every other job in the file, runs with `if: always()`,
and fails unless every needed job succeeded. A failed, cancelled or skipped job fails it.

`scripts/check-ci-gate.mjs` runs first in `ci-passed` and keeps the gate complete. It parses `ci.yml` with a full YAML
parser (`yaml`, a root devDependency), so it reads every key form as GitHub does: quoted, escaped, explicit (`?`),
tagged, anchored or merged. It fails when a job is missing from `needs`, when `ci-passed` loses `if: always()`, or when
any job or step has `continue-on-error`. Without `if: always()`, a failed job would skip `ci-passed`, and GitHub counts
a skipped required check as passed. `continue-on-error` lets a failed job or step count as success. A text scan with
`grep` missed some of these key forms, so the check does not use one.

The same script reads every workflow in `.github/workflows`. It fails on any `uses` that is not a local `./` path, an
action or reusable workflow pinned to a full 40-character commit SHA, or a `docker://` image pinned by digest. It
also fails on a job `container` or a `services` image that is not pinned by digest, and it checks the `uses` of every
local action that a workflow uses, directly or through another local action. A local action can also be a folder in
`.github/workflows`, and the check resolves `..` in the path, so neither hides one. A local Docker action must use a
`docker://` image pinned by digest. A Dockerfile image fails, because its `FROM` line could name a tag, and the ABIP-2
check reads only the Dockerfiles that `docker.yml` publishes. #246
pinned every action. This check stops a later PR from moving one back to a tag, which its owner can move to other
code.

With this job, `ci.yml` needs only one required check. A new job joins the gate when its PR adds it to the `needs`
list, with no settings change. The two checks outside `ci.yml` keep their own names:
`Two-tenant Playwright suite (Chromium + virtual authenticator)` (`e2e.yml`) and `CodeQL` (`codeql.yml`).

New jobs have no `paths` filter. A path-filtered workflow that does not run reports no status, so it could not be a
required check. For that reason Determinism and Terraform check stay outside the summary check. The image scan runs
inside the existing `Build … (…)` jobs of `docker.yml`, so it adds no check name.

Making checks required is a repository setting. It is outside this change.

Alternative considered: list every job name as a required check. Each new job would then need a settings change, and a
renamed job would silently stop being required.

### D13. A new advisory blocks every PR

When a new high or critical advisory appears, the dependency audit fails on every PR until someone fixes the package or
adds a register entry. The same holds for an expired entry. This is the intended behaviour for R3: a gate that passes
unrelated PRs while an advisory is open would not gate the release. The way to unblock is a register entry with a short
expiry and an owner who fixes the advisory before that date. The weekly scan reports entries 14 days before they
expire, so an expiry is not a surprise.

## Risks / Trade-offs

- [The audit, Trivy database or CodeQL depend on outside services] → Each fails closed. A rerun is the remedy. The
  failure message says the tool could not run, not that a finding exists.
- [Aderyn matches by line number, so an unrelated edit above a finding breaks the match] → The job fails with the
  detector and new line, and the fix is a one-line register update. Contract source changes are rare and reviewed.
  An entry left behind after its finding is fixed would accept a later finding of the same detector on the same line,
  so report mode fails on a `slither` or `aderyn` entry that matches no finding. A new finding of the same detector on
  the same line in the same PR still matches the old entry, so a reviewer checks the line when a PR changes a flagged
  contract.
- [A new advisory blocks unrelated PRs] → D13. A short-lived register entry unblocks the team within one PR.
- [Building each image twice in `docker.yml` costs time] → The second build reuses the builder's cache. On PRs the
  second build does not run.
- [Dependabot opens many PRs at first] → Open PR limit of 5 per entry, weekly schedule, 7-day cooldown.
- [Slither's `id` depends on the Slither version] → A Slither upgrade can change IDs. The upgrade PR updates the
  register entries in the same PR.

## Migration Plan

Delivered as a stack of 3 PRs with `gh stack`, merged bottom-up. The split follows the reviewer and the risk:

1. **Register and Solidity analysis** (task group 1). The tech lead reviews it, because it records the contract
   findings.
2. **Dependencies, secrets and source** (task group 2). Small config and workflow files, with no contract or
   publishing impact.
3. **Images** (task group 3). It changes the job that pushes and signs images, so it stays alone and DevOps reviews it.

Rollback is a revert of the PR. No contract, service or infrastructure state changes, so a revert has no side effects.
Task group 4 (R4) runs before the first production release.

## Open Questions

None. Trivy is 0.76.1 (PR 3) and gitleaks is 8.30.1 (PR 2), under the rule in D11.
