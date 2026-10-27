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
| ABIP-2 | Docker Hardened Images | Adopted, with one third-party exception (`giano-devnet`) and one out-of-scope image (`giano-contracts-deployer`) |
| ABIP-5 | External resources in AGENTS.md file | Adopted |
| ABIP-6 | Enforce Minimum Package Age | Adopted: 7 days in both workspaces, no exclusions |
| ABIP-7 | Pin Exact Dependency Versions | In progress (`apply-abips`) |
| ABIP-8 | Key Generation Ceremony | In progress (`apply-abips`) |

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
| `services/custom-example` | 10080 (7 days) | none |

- **No exemption by name or scope.** The blanket entries `postcss`, `baseline-browser-mapping` and
  `@appliedblockchain/*` were removed. Our own releases wait out the window like any other package: the example
  dApp can install a new Giano release only 7 days after it is published.
- **Exclusions.** Only one exact version (`name@x.y.z`) of a direct dependency carrying a critical security fix may be
  excluded. The entry carries a comment with the advisory and the removal date, and the PR description gives the
  reason. List every active exclusion in the table above, and remove it once the version has aged past the window.
- **Lockfiles.** Both lockfiles are committed, and every install in CI and in the Dockerfiles uses
  `--frozen-lockfile`. pnpm 11 checks every lockfile entry against the policy on a frozen install ("Lockfile passes
  supply-chain policies"), so the window also covers versions that are already locked.
- **Package manager.** pnpm 11.15.1, pinned through `packageManager`. ABIP-6 requires at least pnpm 10.16, and 10.19
  for version-specific exclusions.

### Enforcement

`scripts/check-release-age.mjs` runs in CI (`ci.yml`, job "Release-age policy (ABIP-6)"). It fails on any of the
following:
- either workspace with `minimumReleaseAge` below 10080, or unset;
- an exclusion that is not one exact version;
- a `pnpm install` without `--frozen-lockfile` in a workflow or a Dockerfile;
- with `--registry`, which CI passes: an excluded version older than the window, or one that does not exist.

## ABIP-2: Docker Hardened Images (adopted)

ABIP-2 applies because this repository publishes seven container images for non-local environments (the eighth, the one-shot `giano-contracts-deployer`,
is out of scope; see below), and `.github/workflows/docker.yml` is the authoritative list. The migration follows the ABIP-2 companion guide, "Docker
Hardened Images Usage and Migration". The repository-level contract is the `container-images` capability in OpenSpec.

| Image | Final-stage base | Notes |
|-------|------------------|-------|
| `giano-wallet-api` | DHI Node (Alpine) | no shell; runs as `node` (1000) |
| `giano-wallet-byo` | DHI Node (Alpine) | no shell; esbuild bundles at start |
| `giano-bundler` | DHI Node (Alpine) | no shell; entrypoint is `entrypoint.mjs` |
| `giano-contracts-deployer` | `node:22-slim`, **out of scope** | one-shot deploy tool, not a deployed image; see below |
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

### Exceptions

**`giano-devnet` (third-party image, no hardened equivalent).** The local chain is Foundry's `anvil` with a baked
state. No Docker Hardened Image of Foundry or anvil exists.

Mitigations:
- the base is pinned by digest, to the same Foundry release that `determinism.yml` uses;
- the image has no ECR repository;
- it is never deployed to a non-local environment: it is a GHCR artefact for local and CI chains only.

**`giano-contracts-deployer` (out of scope).** It is a one-shot tool that deploys the contracts to a chain (Helm
pre-install Job, compose `deploy` profile), not a service that runs in an environment. It stays on `node:22-slim`
and runs the contracts package's deploy CLI with `tsx`; it deploys committed releases, so it carries no compiler. It is exempted as a whole file (`*` in the block below), and its `docker.yml`
entry is still built and published to GHCR.

Tracking issue: _to be opened (task 8.4 of the `adopt-docker-hardened-images` change)._

The check reads this block, so the documented exceptions and the enforced exceptions are the same list:

```abip-2-exceptions
services/devnet/Dockerfile           ghcr.io/foundry-rs/foundry
packages/contracts/Dockerfile.deployer *
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
`dhi.io/node:22-alpine3.22@sha256:…`. To refresh:

1. Run `docker buildx imagetools inspect dhi.io/<repo>:<tag>` and take the **index** digest (the top-level `Digest:`
   line), not a per-platform manifest digest.
2. Replace the digest in every Dockerfile that uses that tag: `grep -rn 'dhi.io/<repo>:<tag>@' --include='Dockerfile*'`.
3. Open a PR. CI verifies the new digest's signature and rebuilds every image. The e2e suite must pass.

Do not add `apk upgrade` or `apt-get upgrade` steps to pick up a CVE fix. Docker patches DHI images under its
remediation SLA; refresh the digest instead.
