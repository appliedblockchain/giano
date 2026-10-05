## Purpose

The build contract that every container image Giano publishes for a non-local environment meets. It is the
repository's implementation of ABIP-2 (Docker Hardened Images) and its companion migration guide: a hardened,
digest-pinned and signature-verified base; a runtime with no build tooling; non-root execution; and signed, attested
published images.

## ADDED Requirements

### Requirement: Every stage uses a digest-pinned Docker Hardened Image
Every `FROM` instruction and every `COPY --from=<image>` source, in every stage of every image listed in
`.github/workflows/docker.yml`, SHALL reference a Docker Hardened Image from `dhi.io` pinned by SHA256 digest. Two
cases are exempt: a stage named in a recorded exception, and a source that is another stage of the same Dockerfile.
Stages that produce no production artefact (build, install, prune, tools) SHALL use the `-dev` variant. The final stage
SHALL use the runtime (non-`-dev`) variant. No stage SHALL be based on a community image such as `node:*`, `nginx:*` or
`alpine:*`.

#### Scenario: Community base rejected
- **WHEN** a Dockerfile in the image list contains `FROM node:22-alpine AS build`
- **THEN** the repository's Dockerfile policy check fails CI and names the file, the line and the rule

#### Scenario: Tag without digest rejected
- **WHEN** a stage reads `FROM dhi.io/node:22-alpine3.22-dev` without an `@sha256:` digest
- **THEN** the policy check fails CI

#### Scenario: Dev variant in the final stage rejected
- **WHEN** the last stage of a Dockerfile is based on a `-dev` image
- **THEN** the policy check fails CI

### Requirement: Base image signatures are verified before building
Before a CI job builds an image, it SHALL verify the Docker signature of every `dhi.io` digest that the image's
Dockerfile references. A verification failure SHALL fail the build before any layer is built.

#### Scenario: Tampered or unsigned base
- **WHEN** a Dockerfile references a `dhi.io` digest whose signature does not verify against Docker's DHI signing
  identity
- **THEN** the build job fails at the verification step and names the reference

### Requirement: The final stage contains only the runtime
The final stage of each image SHALL consist only of `COPY`, `ENV`, `EXPOSE`, `WORKDIR`, `LABEL`, `VOLUME`,
`HEALTHCHECK`, `STOPSIGNAL` and `ENTRYPOINT`/`CMD` instructions. It SHALL contain no `RUN` instruction. It SHALL contain
only the application's compiled output, its runtime dependencies and the static assets it serves.

Compilers, native-build toolchains (`python3`, `make`, `g++`), package managers (`npm`, `pnpm`, `corepack`, `apk`,
`apt`) and network utilities (`curl`, `wget`) SHALL NOT be present in the final stage. A shell and other utilities
SHALL NOT be present either, except under the SPA tool allowance below. The start command SHALL invoke the runtime
binary directly (`node …` or `nginx …`) and never go through a package manager. Application code that runs in the
final stage SHALL NOT use shell-mode `child_process` APIs (`exec`, `execSync`, or `spawn` with `shell: true`).

#### Scenario: No shell in the Node images
- **WHEN** `docker run --entrypoint sh <image>` is attempted against wallet-api, wallet-byo or bundler
- **THEN** it fails because no shell exists in the image

#### Scenario: RUN in the final stage rejected
- **WHEN** the final stage of a Dockerfile in the image list contains a `RUN` instruction
- **THEN** the policy check fails CI

### Requirement: SPA images add only the minimal start-up tools
On top of the DHI nginx runtime, the final stage of `giano-wallet-web`, `giano-paymaster-admin` and `giano-example`
MAY add exactly `/bin/sh`, `envsubst` and `jq`, together with the shared libraries they need that the runtime lacks.
All of these SHALL be copied from the `-dev` variant of the same DHI nginx image. These images SHALL add no other
binary: no other shell, no stream editor, no network client and no package manager. Utilities that the DHI nginx
runtime ships itself (coreutils and gawk) are part of the base and are not added by this repository. The start-up
scripts of these images SHALL use only the three added binaries and shell built-ins, and SHALL work with a `PATH` that
holds nothing else.

#### Scenario: Only the allowed tools are added
- **WHEN** an SPA image's final filesystem is compared with its DHI nginx base
- **THEN** the only added executables are `sh`, `envsubst` and `jq`; `sed`, `grep`, `curl`, `wget`, `apt` and `apk` are
  absent

#### Scenario: Start-up does not depend on base utilities
- **WHEN** an SPA start-up script runs with `PATH` restricted to `sh`, `envsubst` and `jq`
- **THEN** it renders the same configuration as with the full image

### Requirement: Non-root execution as the DHI user on an unprivileged port
The final stage SHALL run as the non-root user configured by the DHI runtime base. A Dockerfile SHALL NOT switch to any
other user in its final stage or create another user. It SHALL NOT change the entrypoint in a way that causes root
execution. Application files copied into the final stage SHALL be owned by that non-root user. Every container SHALL
listen only on ports of 1024 or above.

#### Scenario: Runs as non-root
- **WHEN** any DHI-based published image starts with no `--user` override
- **THEN** its main process runs with a non-zero UID equal to the base image's configured user

#### Scenario: Writable paths are owned by the runtime user
- **WHEN** a container writes its start-up configuration or its output (the rendered nginx and SPA configuration,
  `/out`)
- **THEN** the write succeeds without root, because the target is owned by the runtime user

### Requirement: Shell-free healthchecks for the Node images
Healthchecks declared in the Node images, and in the repository's compose files for those images, SHALL use the exec
form, SHALL invoke `node` directly, and SHALL NOT depend on a shell, `curl` or `wget`. They SHALL probe the same
endpoint they probe today: `/healthz` for wallet-api, `/` for wallet-byo, and `eth_supportedEntryPoints` for the
bundler. The SPA images, whose final stage has no HTTP client, SHALL declare a liveness check built from shell
built-ins only: the nginx PID file and the rendered configuration file both exist. Their HTTP-level checks remain with
the ALB, Helm `httpGet` probes and `e2e.yml`.

#### Scenario: Compose waits on health
- **WHEN** `docker compose -f deploy/docker-compose.e2e.yml up --build --wait` runs
- **THEN** every service built from this repository reaches `healthy`

### Requirement: Published images are signed and carry SBOM and provenance attestations
Every image published to GHCR SHALL carry an SBOM attestation and a `mode=min` provenance attestation for each platform.
Its manifest list SHALL be signed with keyless Sigstore signing bound to this repository's GitHub workflow identity.
The manifest list copied to ECR SHALL be the same digest as the one published to GHCR, attestations included, and SHALL
be signed by the same workflow identity. The ECR lifecycle budget SHALL retain at least as many deployable commits as it
did before attestations and signatures were added.

#### Scenario: SBOM is retrievable
- **WHEN** `docker buildx imagetools inspect ghcr.io/appliedblockchain/<image>@<digest> --format '{{ json .SBOM }}'`
  runs against a published image
- **THEN** it returns an SPDX SBOM for both `linux/amd64` and `linux/arm64`

#### Scenario: Signature verifies
- **WHEN** `cosign verify` runs against a published digest, with the certificate identity of `docker.yml` on `main`
  and the GitHub OIDC issuer
- **THEN** verification succeeds

#### Scenario: Same bytes in both registries
- **WHEN** a main build publishes an image that has an ECR repository
- **THEN** the ECR tag `<git sha>` resolves to the same manifest-list digest as the GHCR `sha-<short>` tag

### Requirement: Exceptions are recorded
Any image or stage that cannot use a Docker Hardened Image SHALL be listed in `docs/abip-compliance.md`. Each entry
SHALL give:
- the image;
- the reason no hardened equivalent exists;
- the mitigation in place;
- a link to a tracking issue.

The Dockerfile policy check SHALL accept a non-DHI base only for an image listed there. `giano-devnet`, which is built
on the Foundry image, is the recorded exception. `giano-contracts-deployer` is out of scope (a one-shot tool, not a deployed
image) and is exempted as a whole file.

#### Scenario: Recorded exception passes
- **WHEN** the policy check runs over `services/devnet/Dockerfile`, which is listed as an exception
- **THEN** it accepts the digest-pinned Foundry base and still requires the digest pin

#### Scenario: Unrecorded exception fails
- **WHEN** a Dockerfile not listed in `docs/abip-compliance.md` uses a non-DHI base
- **THEN** the policy check fails CI

### Requirement: Images build only with authenticated access to the hardened registry
CI jobs that build images SHALL authenticate to `dhi.io` before building. A build that cannot authenticate, such as a
pull request from a fork without secrets, SHALL fail, naming the missing credential. It SHALL NOT be skipped and SHALL NOT
be reported as a pass.

#### Scenario: Fork pull request
- **WHEN** a pull request from a fork triggers `docker.yml`
- **THEN** the run fails up front with an error naming the missing credential, and no build job is skipped as if it had passed
