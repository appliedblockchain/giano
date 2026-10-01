## Why

ABIP-2 (Docker Hardened Images, status ADOPTED) applies to every repository that produces images for a non-local
environment, and Giano publishes eight. All eight currently build on community bases (`node:22-alpine`,
`node:22-slim`, `nginx:1.27-alpine`, the upstream Foundry image). These ship known critical and high CVEs, a shell and a
package manager at runtime, and in two cases (`giano-bundler`, `giano-contracts-deployer`) they run as root. Published
images are neither attested nor signed: `docker.yml` sets `provenance: false`. Ticket H3 (1 day estimate) asks for every
stage of every image in `.github/workflows/docker.yml` to move to DHI. The migration follows ABIP-2's companion guide,
"Docker Hardened Images Usage and Migration".

## What Changes

- Every stage of the eight images builds on a DHI base pinned by SHA256 digest:
  - build, install, prune and tools stages use the `-dev` variant;
  - the production stage uses the runtime variant.
- Final stages contain only `COPY`, `ENV`, `EXPOSE`, `ENTRYPOINT`/`CMD` and other metadata instructions. They contain
  no `RUN`, no package manager and no build tooling. They run as the DHI non-root user, which owns the application
  files. Start commands invoke `node` or `nginx` directly.
- The Node images (`wallet-api`, `wallet-byo`, `bundler`, `contracts-deployer`) have **no shell** at runtime:
  - the bundler and deployer entrypoints are ported from `/bin/sh` to `.mjs`;
  - `tini` and `curl` go;
  - healthchecks are exec-form `node` probes.
- **The deployer stops loading `hardhat-foundry` at deploy time.** That plugin shells out to `forge`. Instead, the
  Foundry remappings are snapshotted at build time and replayed by a deploy-only Hardhat config. The CREATE2 addresses
  must remain identical, and a merge gate checks it. In line with the guide, `ts-node` script invocations move to
  `tsx`.
- The three SPA images (`wallet-web`, `paymaster-admin`, `giano-example`) move to the DHI nginx runtime, following the
  guide's nginx pattern. Only `sh`, `envsubst` and `jq` (with their libraries) are copied in from the nginx `-dev`
  variant. Their entrypoints are rewritten to need nothing else: no `awk`, `sed`, `tr` or `grep`. The environment
  contract, port `8080` and the HTTP surface are unchanged.
- CI does the following:
  - authenticates to `dhi.io`;
  - **verifies the DHI base-image signatures** before building;
  - attaches SBOM and `mode=min` provenance attestations;
  - **signs published images with keyless cosign**, carrying the signature to ECR on the same digest;
  - raises the ECR lifecycle budget (`var.ecr_lifecycle_image_count`, from 10 to 30) so the extra artefacts do not
    evict deployable commits.
- A dependency-free repository check fails CI on any of the following:
  - a stage not based on `dhi.io/…@sha256:…`;
  - a `-dev` final stage;
  - a `RUN` or `USER` instruction in a final stage;
  - a community base image.
- `giano-devnet` stays on the Foundry image as a documented ABIP-2 third-party exception, with a tracking issue.
  `docs/abip-compliance.md` records the ABIP-2 disposition, the exception and the SPA tool allow-list.
- Deployment is out of this change's critical path: CI secrets, `terraform apply` and the first signed publish and
  rollout are a separate, later task group.

## Capabilities

### New Capabilities
- `container-images`: the build contract every published Giano image meets:
  - a DHI base on every stage, digest-pinned and signature-verified;
  - a final stage that is runtime-only, with no `RUN`;
  - no shell in the Node images, and the minimal tool allow-list in the SPA images;
  - the DHI non-root user on an unprivileged port;
  - healthchecks;
  - signed images with SBOM and provenance attestations;
  - recorded exceptions;
  - enforcement in CI.
- `spa-container-runtime`: the start-up and serving contract of the three SPA images, which their move to the hardened
  nginx runtime must preserve:
  - configuration rendered from `GIANO_*` variables, with the same errors;
  - security headers and CSP;
  - same-origin proxies and upstream re-resolution;
  - SPA fallback and caching;
  - a clean stop.

### Modified Capabilities
None. `demo-deployment` defines the `giano-example` container contract, and every one of its requirements is
unchanged. The rewritten entrypoint must still satisfy them, and the tasks verify that.

## Impact

- **Dockerfiles:**
  - `services/{wallet-api,wallet-web,paymaster-admin,custom-example,bundler,devnet}/Dockerfile`;
  - `e2e/wallet-byo/Dockerfile`;
  - `packages/contracts/Dockerfile.deployer`.
- **Start-up scripts:**
  - `services/{wallet-web,paymaster-admin,custom-example}/docker/entrypoint.sh`: rewritten for `sh`, `envsubst` and
    `jq`;
  - a new minimal `nginx.conf` per SPA;
  - `custom-example/docker/config.js.template`: quoting changes;
  - `services/bundler/entrypoint.sh` → `.mjs`;
  - `packages/contracts/scripts/deployer-entrypoint.sh` → `.mjs`;
  - `e2e/wallet-byo/serve.mjs`: a `SIGTERM` handler.
- **Contracts package:** `hardhat.config.ts` is split into `hardhat.base.ts`, and `hardhat.deploy.config.ts` is added
  with a remapping-snapshot plugin. `tsx` is added as a devDependency at the workspace's existing version. Compile
  output and addresses do not change.
- **CI:**
  - `.github/workflows/docker.yml`: login, base verification, attestations and signing;
  - `.github/workflows/e2e.yml`: login and base verification;
  - `.github/workflows/ci.yml`: the policy check;
  - `scripts/check-dockerfiles.mjs`.
- **Compose:** healthchecks in `deploy/docker-compose.{e2e,infrastructure,infrastructure.aws,dev,reference,sepolia}.yml`.
  Helm probes (`httpGet`) and ECS (ALB checks, `node dist/migrate.js`) need no change. Every port is already 1024 or
  above.
- **Terraform:** the `ecr_lifecycle_image_count` default in `infra/iac/ecr.vars.tf`. Editing it is part of this
  change; applying it is part of the deferred deployment group.
- **Docs and specs:**
  - `docs/abip-compliance.md` (new);
  - `specs/INFRASTRUCTURE.md` and `specs/CI-RELEASE-SPECS.md`;
  - `DEVELOPER-GUIDE.md` and `README.md`: `docker login dhi.io` as a prerequisite for building images.
- **Prerequisite outside the repository:** pulling from `dhi.io` requires an authenticated Docker Hub account.
  - Developers need a free personal account and `docker login dhi.io`.
  - CI needs an org token as repository secrets, through a DevOps request. Until it exists, CI image builds skip with a
    notice.
  - Fork PRs have no secrets, so they skip image builds.
- **Out of scope:**
  - images used only locally in compose (helper `node:22-alpine` services, Postgres, Caddy);
  - automated digest refresh;
  - Docker Scout CVE gating.

  The last two are follow-up issues.
- **Estimate risk:** the deployer rework, because of the `hardhat-foundry` shell dependency, is the largest item. The
  work is likely to exceed the 1-day estimate somewhat.
