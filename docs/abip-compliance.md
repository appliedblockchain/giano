# ABIP Compliance Record

This document records the adoption status of the Applied Blockchain Improvement Proposals (ABIPs) considered for this
repository. It gives the rationale for each disposition, including the ones that are not adopted, so that an omission
reads as a decision rather than an oversight.

## Summary

| ABIP | Title | Status |
|------|-------|--------|
| ABIP-2 | Docker Hardened Images | Adopted, with one third-party exception (`giano-devnet`) |

## ABIP-2: Docker Hardened Images (adopted)

ABIP-2 applies because this repository publishes eight container images for non-local environments, and
`.github/workflows/docker.yml` is the authoritative list. The migration follows the ABIP-2 companion guide, "Docker
Hardened Images Usage and Migration". The repository-level contract is the `container-images` capability in OpenSpec.

| Image | Final-stage base | Notes |
|-------|------------------|-------|
| `giano-wallet-api` | DHI Node (Alpine) | no shell; runs as `node` (1000) |
| `giano-wallet-byo` | DHI Node (Alpine) | no shell; esbuild bundles at start |
| `giano-bundler` | DHI Node (Alpine) | no shell; entrypoint is `entrypoint.mjs` |
| `giano-contracts-deployer` | DHI Node (Debian) | no shell, no `forge`, no `pnpm`; see the runtime-dependency note below |
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

The same entry covers the deployer's build-stage `COPY --from` of `forge`. That `forge` binary compiles the contracts
and never reaches the deployer's final stage.

Tracking issue: _to be opened (task 8.4 of the `adopt-docker-hardened-images` change)._

The check reads this block, so the documented exceptions and the enforced exceptions are the same list:

```abip-2-exceptions
services/devnet/Dockerfile           ghcr.io/foundry-rs/foundry
packages/contracts/Dockerfile.deployer ghcr.io/foundry-rs/foundry
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

### Deployer runtime dependencies

`giano-contracts-deployer` is a one-shot job that runs Hardhat Ignition. Hardhat, Ignition and `tsx` are therefore
runtime dependencies of that image, even though they are devDependencies of the contracts package. They are not build
tooling. Compilation happens in the build stage. The deploy uses a config that does not load `hardhat-foundry`, because
that plugin runs shell commands. It replays the Foundry remappings snapshotted at build time, so the bytecode, and
therefore the CREATE2 addresses, are unchanged.

### Refreshing a pinned digest

Every `FROM` line keeps the human-readable tag next to the digest, for example
`dhi.io/node:22-alpine3.22@sha256:…`. To refresh:

1. Run `docker buildx imagetools inspect dhi.io/<repo>:<tag>` and take the **index** digest (the top-level `Digest:`
   line), not a per-platform manifest digest.
2. Replace the digest in every Dockerfile that uses that tag: `grep -rn 'dhi.io/<repo>:<tag>@' --include='Dockerfile*'`.
3. Open a PR. CI verifies the new digest's signature and rebuilds every image. The e2e suite must pass.

Do not add `apk upgrade` or `apt-get upgrade` steps to pick up a CVE fix. Docker patches DHI images under its
remediation SLA; refresh the digest instead.
