# ABIP Compliance Record

This document records the adoption status of the Applied Blockchain Improvement Proposals (ABIPs) considered for this
repository. It gives the rationale for each disposition, including the ones that are not adopted, so that an omission
reads as a decision rather than an oversight.

## Summary

The register is the Notion database
[ABIPs](https://app.notion.com/p/applied-blockchain/ABIPs-31ab61bd7d5280aca3a9dd968a77b062). Its adopted ABIPs are 1, 2,
5, 6, 7 and 8; ABIP-3 and ABIP-4 do not exist. Bringing the remaining ones in is the OpenSpec change `apply-abips`,
delivered as one stacked PR per ABIP.

| ABIP | Title | Status |
|------|-------|--------|
| ABIP-1 | Branch Protection Rules | In progress (`apply-abips`) |
| ABIP-2 | Docker Hardened Images | Adopted, with one third-party exception (`giano-devnet`, tracked in #165) |
| ABIP-5 | External resources in AGENTS.md file | Adopted |
| ABIP-6 | Enforce Minimum Package Age | Adopted: 7 days in both workspaces; one deviation, `@appliedblockchain/*` excluded in the example |
| ABIP-7 | Pin Exact Dependency Versions | Adopted: every manifest entry and override exact; library peers keep ranges |
| ABIP-8 | Key Generation Ceremony | Adopted: inventory and runbook in [`key-ceremony.md`](key-ceremony.md); the canonical deployer's ceremony is pending with DevOps |

## ABIP-5: External resources in AGENTS.md (adopted)

[`AGENTS.md`](../AGENTS.md) at the repository root follows the ABIP-5 template, and `CLAUDE.md` is the single line
`@AGENTS.md`, so Claude Code loads it at session start. The repository-level contract is the `agent-guidance` capability
in OpenSpec.

| Template section | Disposition |
|------------------|-------------|
| Team | Applied Blockchain team only; there is no client contact to list |
| GitHub | Present. Default permission, with one recorded exception: force-updating the branches of a stack you own after `gh stack rebase` (never `main` or `production`) |
| Jira | Omitted: Giano has no Jira project yet |
| Notion | Present. Giano has no teamspace yet, so the in-scope resources are the `Giano` coordination page and its tickets database (read + write) and the ABIPs register (read only). PM dashboard and Decision Log: none yet |
| Slack | `#giano-dev` only, read only; a PR announcement may be posted only when the user asks |
| Pull requests | Present: trunk-based on `main`, `gh stack` for stacked work, `pnpm lint` before committing, `gh pr checks` before merging, merge commits, Conventional Commits, no AI attribution |

Keep `AGENTS.md` current: a change to the team, the external systems or the PR conventions updates it in the same PR.
When Giano gets a teamspace or a Jira board, add them there.

## ABIP-6: Enforce Minimum Package Age (adopted)

Giano is a wallet, so it takes the ABIP's 7-day tier for projects that handle financial transactions, rather than the
3-day floor. The repository-level contract is the `dependency-security` capability in OpenSpec.

| Workspace | `minimumReleaseAge` | Active exclusions |
|-----------|---------------------|-------------------|
| root (`pnpm-workspace.yaml`) | 10080 (7 days) | none |
| `services/custom-example` | 10080 (7 days) | `@appliedblockchain/*` (deviation, below) |

- **No exemption by name or scope for third-party packages.** The blanket entries `postcss` and
  `baseline-browser-mapping` were removed.
- **Deviation: our own `@appliedblockchain/*` scope.** ABIP-6 says internal packages are not exempt and that blanket
  exclusions must not be used. Giano departs from that for its own scope, in `services/custom-example` only (the root
  workspace links its packages with `workspace:` and installs none from the registry):
  - **Why.** These packages are built and published by this repository's `release.yml` from reviewed commits on
    `main`, so the window guards against nothing a third-party package would bring. Without the entry the example,
    which shows what an integrator installs, lags every Giano release by 7 days, and so do the `giano-example` image
    and the e2e suite that install it.
  - **Bounds.** The checker allows exactly `@appliedblockchain/*`; any other name or scope still fails, as does a
    single internal package by name. Third-party dependencies of our packages still face the full window.
  - **Approval.** Decided by the team on 2026-10-28 (PR #162). It needs the tech lead's sign-off, and it is to be
    raised with the ABIPs owners as an amendment to ABIP-6. Remove the entry if that amendment is rejected.
- **Exclusions.** For a third-party package, only one exact version (`name@x.y.z`) of a direct dependency carrying a critical security fix may be
  excluded. The entry carries a comment with the advisory and the removal date, and the PR description gives the
  reason. List every active exclusion in the table above, and remove it once the version has aged past the window.
- **Lockfiles.** Both lockfiles are committed, and every install in CI and in the Dockerfiles uses
  `--frozen-lockfile`. pnpm checks every lockfile entry against the policy on a frozen install ("Lockfile passes
  supply-chain policies"), so the window also covers versions that are already locked.
- **Package manager.** pnpm 12.17.0, pinned through `packageManager` with its sha256 in both workspaces. ABIP-6
  requires at least pnpm 10.16, and 10.19 for version-specific exclusions. The pnpm version itself also respects the
  window: pick a release published at least 7 days before the PR that moves the pin.

### Enforcement

`scripts/check-release-age.mjs` runs in CI (`ci.yml`, job "Release-age policy (ABIP-6)"). It fails on any of the
following:
- either workspace with `minimumReleaseAge` below 10080, or unset;
- an exclusion that is not one exact version, other than `@appliedblockchain/*`;
- a `pnpm install` without `--frozen-lockfile` in a workflow or a Dockerfile;
- with `--registry`, which CI passes: an excluded version older than the window, or one that does not exist.

The dependency audit runs in CI too (`ci.yml`, job "Dependency audit (pnpm audit)"), on every pull request and in the
CI run `release.yml` calls. It runs `pnpm audit` on both workspaces and fails on a high or critical advisory that is not
in the accepted-findings register, [`security/accepted-findings.json`](../security/accepted-findings.json). It also
fails when the audit cannot run. The register is the only place an advisory left open is accepted: each entry gives the
reason, one owner and an expiry date, and moderate and low advisories left open are recorded there too
([`security/README.md`](../security/README.md)). The `dependency-security` capability in OpenSpec sets the rule.

Dependabot ([`.github/dependabot.yml`](../.github/dependabot.yml)) opens version update PRs for both workspaces with a
7-day `cooldown`, so it proposes no version younger than the window. Its PRs keep every pin exact (ABIP-7).

## ABIP-7: Pin Exact Dependency Versions (adopted)

Every manifest in the repository is in scope: the root, `packages/*`, `services/*` (including the separate
`services/custom-example` workspace) and `e2e`, 14 in all. The repository-level contract is the `dependency-pinning`
capability in OpenSpec.

- **Exact versions.** Every `dependencies`, `devDependencies` and `optionalDependencies` entry is an exact version.
  `workspace:` references are kept, because they resolve to exact versions at install and publish time.
- **Peer dependencies.** The seven published `@appliedblockchain/*` libraries (non-private `packages/*` with
  `publishConfig`) keep semver ranges on their `peerDependencies`, for example `viem ^2.31.0` and `react >=18`, so
  integrators choose those versions themselves. That is ABIP-7's exemption, and the only one used. Every other field
  in those libraries is exact.
- **Overrides.** The security floors in both `pnpm-workspace.yaml` files have exact values. Their selector keys keep
  the range that scopes which resolutions they replace, for example `"ws@>=8.0.0 <8.21.0": "8.21.0"`.
- **How the pins were chosen.** Each range was replaced with the version its lockfile already resolved, and each
  override value with the version it already resolved to (or its floor, for an override nothing currently matches).
  Only the lockfiles' `specifier` and `overrides` lines changed; every resolved package and snapshot is byte-identical.
  The published libraries' runtime dependencies are therefore the versions they already shipped with (changeset
  `exact-dependency-pins`).
- **Git, tarball and `file:` dependencies.** There are none. The checker accepts a git dependency only at a
  40-character commit SHA. The Foundry dependencies are git submodules, pinned by commit.
- **Not adopted yet: `catalog:`.** ABIP-7 recommends a pnpm catalog in monorepos. It is a separate mechanical
  rewrite, kept out of this change so the pin diff stays reviewable, and `services/custom-example` cannot share the
  root catalog. It is a follow-up.

### Enforcement

`scripts/check-pinned-versions.mjs` runs in CI on every pull request, and in the CI run `release.yml` calls (job
"Exact dependency pins (ABIP-7)"). It fails on any non-exact manifest entry outside the library peer exemption, and on
any non-exact override value. Transitive ranges are the lockfile's job and are out of scope.

### Tools installed outside npm

The security tools CI installs from outside npm (pip packages and release binaries) follow ABIP-6 and ABIP-7 too. The
repository-level contract is the `ci-security-gates` capability in OpenSpec.

- **Exact version.** Never `latest`, a major tag or a version range.
- **At least 7 days old.** The version was released at least 7 days before the PR that adopts it.
- **Integrity hash.** A pip package is installed from a hash-locked requirements file with `pip install
  --require-hashes`. A release binary is checked with `sha256sum -c` against the sha256 in the workflow's `env`, next to
  the version and a comment with the release date. A mismatch fails the job before the tool runs.

Dependabot does not update these tools. Update them by hand under the same rule, in a PR that also updates the table
below and any register entry whose finding ID the new version changes (`security/README.md`). The rule is not checked
automatically: checking release dates would need network access to each project's release page.

| Tool | Version | Released | Integrity check | Where it is pinned |
|------|---------|----------|-----------------|--------------------|
| Slither | 0.11.6 | 2026-07-28 | hash-locked pip requirements; every dependency also at least 7 days old (`uv pip compile --exclude-newer`) | `packages/contracts/requirements-ci.in` and `requirements-ci.txt` |
| Aderyn | 0.6.8 | 2026-01-22 | sha256 of `aderyn-x86_64-unknown-linux-gnu.tar.xz` | `ci.yml`, job `solidity-analysis` (`ADERYN_VERSION`, `ADERYN_SHA256`) |
| gitleaks | 8.30.1 | 2026-03-21 | sha256 of `gitleaks_8.30.1_linux_x64.tar.gz` | `ci.yml`, job `secret-scan` (`GITLEAKS_VERSION`, `GITLEAKS_SHA256`) |
| CodeQL (`github/codeql-action`) | 4.39.1 | 2026-10-21 | the commit SHA of the release (`9b3254085494b55a0f7c4c2b3d2d52cc712ce370`), as #246 pins every action; the action downloads its own CodeQL bundle | `codeql.yml` (`init` and `analyze`) |
| Trivy | 0.76.1 | 2026-10-21 | sha256 of `trivy_0.76.1_Linux-64bit.tar.gz` and `trivy_0.76.1_Linux-ARM64.tar.gz`. Both match the release's checksums file and GitHub's asset digests. | `docker.yml`, job `build`, and `security-scan.yml`, job `images` (`SCAN_TRIVY_VERSION`, `SCAN_TRIVY_SHA256_AMD64`, `SCAN_TRIVY_SHA256_ARM64`) |

## ABIP-8: Key Generation Ceremony (adopted)

The key inventory and the Giano runbook are in [`key-ceremony.md`](key-ceremony.md). The repository-level contract is
the `production-key-ceremony` capability in OpenSpec. Ceremonies are run by DevOps; the repository makes sure nothing
in it needs, or tells anyone to hold, a production key:

- **The canonical deployers are out of scope.** There are two independent development-team keys, one per network class
  (mainnet, testnet), kept in 1Password. A deployer only places contracts at addresses and holds no role or funds on
  them once deployment ends, so neither goes through an ABIP-8 ceremony (`docs/key-ceremony.md`). A testnet adoption
  never touches the mainnet key.
- **Verify-only deploys.** `deploy:cli core` / `testing` without `DEPLOYER_PRIVATE_KEY` check every contract against a
  release's code and send nothing. A missing contract fails the run, pointing to the development team. The
  `giano-contracts-deployer` image and the Helm pre-install Job run this way. The chart says never to put the key in a
  client's secret.
- **Docs.** `packages/contracts/README.md`, `specs/INFRASTRUCTURE.md`, `specs/INTEGRATION.md`,
  `specs/DEVELOPER-GUIDE.md` and `specs/CHAIN-ADOPTION.md` no longer hand a developer or a client the canonical
  deployer key. Adoption is a DevOps operation.
- **Production signing** stays in the HSM. wallet-api refuses an in-process sponsorship signer in the `production`
  class, now covered by a test.

| Pending | Owner |
|---------|-------|
| Ceremony for the permanent canonical deployer, then the placeholder switch in `deploy/config.ts` | DevOps, then the tech lead |
| Confirm that the development team has no read access to the `Giano prd` 1Password vault | DevOps |
| prd sponsorship signer (in the HSM), bundler executor, timelock and operator keys, by ceremony, when prd is provisioned | DevOps |
| Retire `deploy/sepolia/` (keeps `CANONICAL_DEPLOYER_PRIVATE_KEY` in a local `.env`); #160 replaces it | #160 |

## ABIP-2: Docker Hardened Images (adopted)

ABIP-2 applies because this repository publishes eight container images, and `.github/workflows/docker.yml` is the
authoritative list. The migration follows the ABIP-2 companion guide, "Docker
Hardened Images Usage and Migration". The repository-level contract is the `container-images` capability in OpenSpec.

| Image | Final-stage base | Notes |
|-------|------------------|-------|
| `giano-wallet-api` | DHI Node (Alpine) | no shell; runs as `node` (1000) |
| `giano-wallet-byo` | DHI Node (Alpine) | no shell; esbuild bundles at start |
| `giano-bundler` | DHI Node (Alpine) | no shell; entrypoint is `entrypoint.mjs` |
| `giano-contracts-deployer` | DHI Node (Alpine) | no shell; the deploy CLI bundled into one file, no `node_modules`; runs as `node` (1000) |
| `giano-wallet-web` | DHI nginx (Debian) | SPA tool allow-list; runs as `nginx` (65532) |
| `giano-paymaster-admin` | DHI nginx (Debian) | SPA tool allow-list |
| `giano-example` | DHI nginx (Debian) | SPA tool allow-list |
| `giano-devnet` | Foundry, **exception** | see below |

### Enforcement

`scripts/check-dockerfiles.mjs` runs in CI (`ci.yml`) and fails on any of the following, in any Dockerfile that
`docker.yml` lists:
- a stage or `COPY --from=<image>` source that is not `dhi.io/…@sha256:…`;
- a `-dev` final stage;
- a non-`-dev` intermediate stage;
- a `RUN` or `USER` instruction in a final stage;
- a non-DHI reference that is not listed in the exceptions block below.

`docker.yml` also verifies the signature of every DHI base before building, and it publishes images with SBOM and
provenance attestations and a keyless cosign signature. To verify a base by hand:

```
cosign verify dhi.io/<repo>:<tag>@sha256:<index digest> \
  --key https://registry.scout.docker.com/keyring/dhi/latest.pub \
  --insecure-ignore-tlog=true --experimental-oci11
```

DHI signs the multi-arch index and attaches the signature as an OCI 1.1 referrer, which is why `--experimental-oci11`
is needed. Its signatures are not in the public Rekor log, which is why the transparency-log check is skipped and the
signature is verified by key.

**Vulnerability scan (G25).** Each `build` job in `docker.yml` first builds its image to a tar and scans it with Trivy,
before anything is pushed. The job fails on a HIGH or CRITICAL vulnerability that has a fixed version and no entry in
[`security/accepted-findings.json`](../security/accepted-findings.json). It also fails when Trivy detects no OS in the
image, or an OS that is end of life. On a PR the job stops after the scan. On `main`, tags and manual runs, the existing
push step follows. It reuses the scanned layers, and a last step fails the job if the pushed layers differ from the
scanned ones. The `merge` job, which tags, copies to ECR and signs, needs every `build` job, so a failed scan leaves
nothing tagged or signed. `security-scan.yml` scans the `latest` tag of every image again each week. A fix comes from a
DHI digest refresh (below) where one exists; otherwise the finding needs a register entry (`security/README.md`).

### Exceptions

**`giano-devnet` (third-party image, no hardened equivalent).** The local chain is Foundry's `anvil` with a baked
state. No Docker Hardened Image of Foundry or anvil exists.

Mitigations:
- the base is pinned by digest, to the same Foundry release that `determinism.yml` uses;
- the image has no ECR repository;
- it is never deployed to a non-local environment: it is a GHCR artefact for local and CI chains only.

Tracking issue: [#165](https://github.com/appliedblockchain/giano/issues/165).

`giano-contracts-deployer` was previously exempted as a whole file, as a one-shot tool rather than a deployed image.
That exemption is gone (`apply-abips`). ABIP-2's exceptions cover only third-party images. The deployer also runs in
client clusters (Helm pre-install Job) and is handed deployer credentials, so it gets the same hardening as every
other image. Its CLI is bundled with every dependency into `dist-deployer/cli.mjs` (`tsdown.deployer.config.mts`).
The runtime holds node, that file, the releases and the CreateX deployment data, and nothing else. The check rejects
a whole-file `*` entry.

The check reads this block, so the documented exceptions and the enforced exceptions are the same list:

```abip-2-exceptions
services/devnet/Dockerfile           ghcr.io/foundry-rs/foundry
```

### SPA tool allow-list (applied guideline, not an exception)

The three SPA images render their runtime configuration at container start (the Baanx build-once, deploy-anywhere
pattern). This is the guide's "Nginx and Frontend Services" case. Exactly `/bin/sh`, `envsubst` and `jq`, with the
two libraries `jq` links that the runtime lacks, are copied from the DHI nginx `-dev` image into the hardened nginx
runtime by `deploy/docker/stage-spa-tools.sh`.

The start-up scripts use only those three tools and shell built-ins. `scripts/spa-parity` runs them with `PATH`
holding nothing else, and checks that they render what the previous images rendered for every environment the
repository uses. Nothing else is added. The DHI nginx base itself ships coreutils and gawk, but no `sed`, no `grep`, no
network client and no package manager. Those base utilities are Docker's, under its patch SLA, and the start-up does
not use them.

### Refreshing a pinned digest

Every `FROM` line keeps the human-readable tag next to the digest, for example
`dhi.io/node:24-alpine3.23@sha256:…`. To refresh:

1. Run `docker buildx imagetools inspect dhi.io/<repo>:<tag>` and take the **index** digest (the top-level `Digest:`
   line), not a per-platform manifest digest.
2. Replace the digest in every Dockerfile that uses that tag: `grep -rn 'dhi.io/<repo>:<tag>@' --include='Dockerfile*'`.
3. Open a PR. CI verifies the new digest's signature and rebuilds every image. The e2e suite must pass.

Do not add `apk upgrade` or `apt-get upgrade` steps to pick up a CVE fix. Docker patches DHI images under its
remediation SLA; refresh the digest instead.
