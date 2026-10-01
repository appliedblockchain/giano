## 1. Confirm the DHI catalogue (prerequisite: `docker login dhi.io` with a Docker Hub account)

- [x] 1.1 Resolve the multi-arch index digests for each tag in design D1, with `docker buildx imagetools inspect`:
  - Node Alpine, `-dev` and runtime;
  - Node Debian, `-dev` and runtime;
  - nginx Debian, `-dev` and runtime.

  Confirm that each index lists `linux/amd64` and `linux/arm64`. Confirm that the Alpine `-dev` and runtime tags share
  an Alpine version. Record tag → digest in the design if a name differs from D1.
- [x] 1.2 Read each runtime image's config: `User` (numeric UID:GID), `PATH`, `Entrypoint`/`Cmd` and `StopSignal`.
  Confirm that `/bin/sh` is absent. For nginx, also read the shipped `/etc/nginx/nginx.conf`, the `pid` and temp paths,
  and which directories are writable by the runtime user. Record the findings in the design.
- [x] 1.3 In the nginx `-dev` image, confirm how `sh`, `envsubst` and `jq` are provided (present already, or via
  `apt-get`), and list their shared libraries with `ldd`.
- [x] 1.4 Confirm Docker's documented verification of DHI signatures (`cosign verify` with the DHI public key, or
  `docker scout attest`), and the cosign mode for carrying our signatures to ECR (`cosign copy` or OCI 1.1 referrers).
  Record the exact commands in the design.

## 2. Dockerfile policy check (lands first, so every later step is enforced)

- [x] 2.1 Create `docs/abip-compliance.md` with:
  - the summary table (ABIP-2: Adopted with exception);
  - the ABIP-2 section;
  - a machine-readable exceptions block listing `services/devnet/Dockerfile` and the deployer's build-stage `forge`
    source;
  - the SPA tool allow-list (`sh`, `envsubst`, `jq`), recorded as an applied guideline;
  - the digest-refresh procedure (design D7).
- [x] 2.2 Write `scripts/check-dockerfiles.mjs` (no dependencies). It reads the image list from
  `.github/workflows/docker.yml`, parses the stages, and enforces:
  - a `dhi.io` host plus an `@sha256:` digest;
  - `-dev` everywhere except the final stage;
  - only the allowed instructions in the final stage, with no `RUN` and no `USER`;
  - no community bases;
  - the exceptions block.

  It must report file:line:rule. Export its reference parser for task 7.1.
- [x] 2.3 Add `node:test` cases, one per policy scenario:
  - community base;
  - tag without digest;
  - `-dev` final stage;
  - `RUN` in the final stage;
  - `USER` in the final stage;
  - recorded exception passes but still needs a digest;
  - unrecorded exception fails.
- [x] 2.4 Wire the check into `.github/workflows/ci.yml`. It must not need registry credentials. It is expected to fail
  until group 6 is complete.

## 3. Node images on DHI

- [x] 3.1 Migrate `services/wallet-api/Dockerfile` to DHI:
  - the build stage uses the `-dev` image, with `PATH` set to `/opt/nodejs/bin` and `corepack enable`, and runs
    `pnpm deploy --prod`;
  - the runtime stage uses `COPY --chown`, with no `RUN` and no `USER`, and an exec-form `node -e` healthcheck on
    `/healthz`.

  Verify: the image builds on both architectures, it runs as UID ≠ 0, `node dist/migrate.js` works, and it serves in
  the e2e stack. This last check covers the guide's `.js` extension, JSON asset and `NODE_ENV` items.
- [x] 3.2 Port `services/bundler/entrypoint.sh` to `entrypoint.mjs`:
  - the same required variables and defaults;
  - the same refusal to run with the Anvil key and the same `GIANO_DEV_MODE` wording;
  - start alto in-process or with a non-shell `spawn`.

  Add `node:test` cases for the refusal rules. Run alto in the image to confirm it makes no shell-mode
  `child_process` calls.
- [x] 3.3 Migrate `services/bundler/Dockerfile`:
  - in the `-dev` stage, `npm install --prefix /app @pimlico/alto@0.0.18`;
  - the runtime stage copies `/app` and `entrypoint.mjs` with `--chown`, with an exec-form `node` POST healthcheck.

  Delete `entrypoint.sh`. Remove `tini` and `curl`.
- [x] 3.4 Migrate `e2e/wallet-byo/Dockerfile`:
  - remove `tini` and `curl`;
  - add a `SIGTERM` handler to `serve.mjs`;
  - set `ENTRYPOINT ["node","serve.mjs"]`;
  - copy `/repo` with `--chown`;
  - add an exec-form healthcheck on `/`.

  Verify: esbuild bundles at start without a shell, and `docker stop` exits well before the timeout.
- [x] 3.5 Split `packages/contracts/hardhat.config.ts` into `hardhat.base.ts`, holding the solidity settings, networks
  and paths. Then:
  - `hardhat.config.ts` = base + `hardhat-foundry` + the dev plugins, unchanged in behaviour;
  - add `hardhat.deploy.config.ts` = base + toolbox + ignition + a remapping override that reads
    `foundry.snapshot.json`.

  Verify: `pnpm hh:compile` produces byte-identical artefacts before and after the split.
- [x] 3.6 Port `packages/contracts/scripts/deployer-entrypoint.sh` to `deployer-entrypoint.mjs`:
  - Hardhat is run through `node node_modules/hardhat/internal/cli/bootstrap.js --config hardhat.deploy.config.ts`;
  - `gen:addresses` and the registry JSON step are run with `node --import tsx`;
  - `tsx` is added to the contracts devDependencies at the workspace's existing version;
  - it keeps the same variables, defaults and output file name.

  Migrate `Dockerfile.deployer`:
  - the Debian `-dev` build stage runs `hh:compile` with the pinned `forge`, writes `foundry.snapshot.json`, and runs
    `pnpm deploy`, creating `/out` and `/deployments`;
  - the Debian runtime stage uses `COPY --chown`, with no `forge`, no `RUN` and no `USER`.

  **Merge gate:** deploy from the image to the devnet, then confirm that the addresses equal the committed
  `addresses.ts` for chain 31337 and that `/out/giano-addresses.31337.json` is written. If Hardhat's `ts-node` hook
  fails on the runtime, transpile the deploy config to JS in the build stage, then re-run this check.

## 4. SPA golden fixtures (before any entrypoint changes)

- [x] 4.1 Run each existing `entrypoint.sh` (wallet-web, paymaster-admin, custom-example) on the host, with `exec nginx`
  stubbed out and paths redirected to a temporary directory. Run it for every environment the repository uses:
  - `deploy/docker-compose.e2e.yml`;
  - `docker-compose.infrastructure*.yml`;
  - `docker-compose.{dev,reference,sepolia}.yml`;
  - the Helm defaults;
  - the error cases.

  Commit the rendered browser configuration and the rendered `default.conf` as fixtures.
- [x] 4.2 Add a `node:test` parity harness that runs a given entrypoint the same way and compares its output with the
  fixtures, semantically for JSON and JS, and normalised for nginx configuration.

## 5. SPA images on DHI nginx

- [x] 5.1 Rewrite `services/wallet-web/docker/entrypoint.sh` to use only `sh` built-ins, `envsubst` and `jq` (the `awk`
  resolver read becomes `while read`). Pass the parity harness.
- [x] 5.2 Check `services/paymaster-admin/docker/entrypoint.sh` against the allow-list, and adjust it if it needs
  anything else. Pass the parity harness, including the malformed-JSON exit.
- [x] 5.3 Rewrite `services/custom-example/docker/entrypoint.sh` to use `jq` for chain parsing, JSON and JS escaping,
  and the `GIANO_RPC_UPSTREAM_<id>` lookup, with no `sed`, `tr`, `grep` or `eval`. Switch `config.js.template` to
  double-quoted literals. Pass the parity harness and the `demo-deployment` scenarios "Placeholder substitution only"
  and "Keyed RPC via proxy".
- [x] 5.4 ~~Add a minimal `nginx.conf` for each SPA.~~ Not needed. Task 1.2 found that the DHI nginx
  image already lets its runtime user (65532) write `/etc/nginx/conf.d`, `/run/nginx` (the PID file)
  and `/var/cache/nginx`, so the base `nginx.conf` is used unchanged. The entrypoints keep their
  original paths: templates in `/etc/giano/`, the server block rendered to
  `/etc/nginx/conf.d/default.conf`.
- [x] 5.5 Migrate the three SPA Dockerfiles:
  - the `build` stage uses the DHI Node `-dev` image;
  - the `tools` stage uses the DHI nginx `-dev` image and stages `sh`, `envsubst`, `jq` and their `ldd` libraries
    under `/tools/`, plus the writable directories owned by the runtime UID:GID;
  - the final stage uses DHI nginx with `COPY --from=tools /tools/ /`, `COPY --chown` of `dist/` and the templates,
    `COPY --chmod=0755` of the entrypoint, and `ENTRYPOINT ["/entrypoint.sh"]`;
  - the healthcheck uses shell built-ins on the PID and rendered-config files;
  - no `RUN` and no `USER`.
- [x] 5.6 Check header parity against the running containers: `curl -I` from the host for `/`, `/assets/*`, the
  configuration file and a deep route, compared with the headers the previous images sent. Also check the wallet-web
  upstream re-resolution by restarting `wallet-api` in compose with a new IP.

## 6. Compose, docs and the policy check going green

- [x] 6.1 Replace the `CMD-SHELL curl|wget` healthchecks for images built from this repository with the D4 forms, in
  `deploy/docker-compose.{e2e,infrastructure,infrastructure.aws,dev,reference,sepolia}.yml`. Leave third-party services
  unchanged.
- [x] 6.2 Run `node scripts/check-dockerfiles.mjs` and confirm it passes for all eight Dockerfiles.
- [x] 6.3 Update the docs:
  - `specs/INFRASTRUCTURE.md`: the SPA image layout, the hardened runtime, the `provenance: false` rationale, and
    signing;
  - `specs/CI-RELEASE-SPECS.md`: attestations, signing, base verification and the ECR budget;
  - `DEVELOPER-GUIDE.md` and `README.md`: `docker login dhi.io` as a prerequisite for building images.
- [x] 6.4 Add a changeset for `@appliedblockchain/giano-contracts` only if the published package changes. The Hardhat
  config split and `tsx` are dev-only, so this is expected to be "no changeset". Record the reason in the PR.

## 7. CI wiring (merged dormant; activates when the secret exists)

- [x] 7.1 Change `docker.yml` `build`:
  - add the `dhi.io` login (`DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`), with notice-and-skip when the secret is empty;
  - verify the base-image signatures with the task 1.4 command, over the references the task 2.2 parser extracts;
  - replace `provenance: false` with `provenance: mode=min` + `sbom: true`;
  - rewrite the attestation comment.
- [x] 7.2 Change `docker.yml` `merge`: install cosign, keyless-sign the GHCR list digest, and carry the signature to
  ECR in the task 1.4 mode. Verify both registries with `cosign verify`.
- [x] 7.3 Change `e2e.yml`: add the `dhi.io` login and base verification before `compose up --build`, with the same
  notice-and-skip.
- [x] 7.4 Change `infra/iac/ecr.vars.tf`: raise `ecr_lifecycle_image_count` to 30 for dev, stg and prd, with the
  reasoning in the description. Run `terraform fmt` and validate. Do not apply.

## 8. Local end-to-end verification

- [x] 8.1 Build all eight images locally for the host architecture, and also for the other architecture for at least
  wallet-api, the deployer and one SPA.
- [x] 8.2 Run `docker compose -f deploy/docker-compose.e2e.yml up --build --wait` and the full Playwright suite. All
  tests must pass.
- [x] 8.3 Run spot checks following the spec scenarios:
  - the Node images have no `sh`;
  - the SPA images contain only `sh`, `envsubst` and `jq` from the tool list (no `ls`, `cat`, `sed`, `awk`, `grep`,
    `tr`, `curl`, `wget`, `apt` or `apk`);
  - every image runs as UID ≠ 0;
  - the deployer contains no `forge`, `pnpm`, `python3` or `g++`;
  - a local `docker buildx build --sbom=true --provenance=mode=min` can be inspected.
- [ ] 8.4 Open the tracking issue for the `giano-devnet` exception and link it in `docs/abip-compliance.md`. Open
  follow-up issues for automated digest refresh and for Docker Scout CVE gating.

## 9. Deployment (deferred, callable later)

- [ ] 9.1 Raise a DevOps request (`/ae-devops-request`) for a Docker Hub token with `dhi.io` pull access, stored as
  repository secrets `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`.
- [ ] 9.2 Once the secret exists, re-run `docker.yml` and `e2e.yml` on the PR. Base verification and the builds must be
  green on both architectures before merge.
- [ ] 9.3 Run `terraform apply` for the ECR lifecycle change in dev, before the first attested publish reaches ECR.
- [ ] 9.4 After the merge to `main`, verify the following:
  - SBOMs are retrievable for both platforms on GHCR;
  - `cosign verify` passes on GHCR and ECR;
  - the ECR `<sha>` tag has the same digest as GHCR `sha-<short>`;
  - `aws ecr describe-images` confirms the per-commit image count assumed in design D6. If it differs, adjust 7.4.
- [ ] 9.5 Roll out to dev ECS with `image_tag=<sha>`, then smoke-test each service:
  - every ALB target is healthy;
  - wallet-web `/config.json` and `/api/healthz`;
  - paymaster-admin `/rpc/<id>`;
  - giano-example on both tenants;
  - the wallet-byo `/.well-known/webauthn`;
  - a sponsored userop through the bundler;
  - a deployer run against a test chain.

  Rollback: `image_tag=<previous sha>`.
