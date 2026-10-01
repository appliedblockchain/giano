## Context

See `proposal.md` for the motivation. Two documents govern this change: ABIP-2, which is the policy, and its companion
**"Docker Hardened Images Usage and Migration"** guide, which describes how to implement it. Where the guide is more
specific than ABIP-2, this design follows the guide. The guide is the source of these rules: no `RUN` in the final
stage, verify base-image signatures, sign published images, the nginx tool-copy pattern, and `ts-node` → `tsx`.

The eight images in `.github/workflows/docker.yml` fall into four shapes:

| Shape | Images | Final stage today | What breaks on a shell-free runtime |
| --- | --- | --- | --- |
| Node service, compiled | `giano-wallet-api` | `node:22-alpine`; `apk add curl`; `USER node` | `curl` healthcheck only |
| Node service, run from source | `giano-wallet-byo`, `giano-bundler`, `giano-contracts-deployer` | `node:22-alpine` / `node:22-slim`; `tini`; `curl`; corepack/pnpm at start; `/bin/sh` entrypoints; bundler and deployer run as root | `sh` entrypoints, `tini`, `pnpm` at start, `curl` healthchecks, and **`hardhat-foundry` shelling out** (see D3) |
| Static SPA behind nginx | `giano-wallet-web`, `giano-paymaster-admin`, `giano-example` | `nginx:1.27-alpine`; `apk add curl [jq]`; `RUN chown/sed`; `USER nginx` | `sh` plus `envsubst`, `jq`, `awk`, `sed`, `tr` and `grep` in the entrypoints; `RUN` in the final stage; `curl` healthchecks |
| Third-party tool image | `giano-devnet` | the Foundry image, digest-pinned | out of reach: no hardened Foundry image exists |

Constraints that shape the approach:

- **The DHI runtime variants have no shell and no package manager.** The guide also says the final stage may contain
  only `COPY`, `ENV`, `EXPOSE`, `USER` and `CMD`/`ENTRYPOINT` instructions, with no `RUN`.
- **`dhi.io` refuses anonymous pulls** (401 from the token endpoint, checked on 2026-09-30). Every build, in CI and
  locally, needs a Docker Hub login.
- **`@nomicfoundation/hardhat-foundry` uses shell-mode `child_process`.** It calls `exec` and `execSync` for
  `forge config` and `forge remappings` when the Hardhat config loads (`dist/src/foundry.js`). On a shell-free runtime
  this fails with `spawn /bin/sh ENOENT`.
- **The CREATE2 addresses depend on the contracts bytecode.** Bytecode depends on the solc version, the settings and
  the remappings that `hardhat-foundry` produces. None of these may change.
- **The ECR lifecycle policy expires on `tagStatus: any` past `var.ecr_lifecycle_image_count` (10).** That is why
  `docker.yml` sets `provenance: false` today.
- **ECS runs ARM64, and `docker.yml` builds both architectures natively.** Every chosen DHI tag must publish both
  `linux/amd64` and `linux/arm64`.
- **Every service already listens on a port of 1024 or above** (8080, 4337, 8545). The guide's privileged-port step
  needs no change to Helm, ECS or the ALB.
- **Migrations already call `node` directly** (`node dist/migrate.js`, in ECS, compose and Helm).

## Goals / Non-Goals

**Goals:**
- The eight images meet `specs/container-images`. Seven are on DHI; `giano-devnet` is a recorded exception.
- The three SPA images keep their external contract exactly, as specified in `specs/spa-container-runtime` and in the
  existing `demo-deployment` capability. Compose files, Helm values and ECS task definitions need no new variables.
- The rules are enforced by a CI check, not by review discipline.
- All work up to, but not including, deployment can be completed and verified locally with a personal `dhi.io` login.

**Non-Goals:**
- Images that only ever run locally: the `node:22-alpine` helper services in compose, Postgres, Caddy and similar.
- Automating digest refresh with Renovate or Dependabot. This is a follow-up issue; this change documents the manual
  refresh procedure instead.
- CVE scanning gates (Docker Scout). The guide lists Scout as a reference, not a requirement. It is a follow-up issue.
- Kubernetes `securityContext` hardening in the Helm chart. The chart is not deployed anywhere today.

## Decisions

### D1. Base images

| Image | Non-final stages (`-dev`) | Final stage (runtime) |
| --- | --- | --- |
| wallet-api, wallet-byo, bundler | `dhi.io/node:22-alpine3.23-dev@sha256:d3e2…053f` | `dhi.io/node:22-alpine3.23@sha256:920a…07f4d` |
| contracts-deployer | `dhi.io/node:22-debian13-dev@sha256:51ae…704d` (glibc for `forge` and solc at build time) | `dhi.io/node:22-debian13@sha256:abf0…74d2` |
| wallet-web, paymaster-admin, giano-example | build: `dhi.io/node:22-alpine3.23-dev`; tools: `dhi.io/nginx:1.29-debian13-dev@sha256:069b…bbff` | `dhi.io/nginx:1.29-debian13@sha256:d457…87dd` |
| devnet | — (exception, D8) | Foundry image, digest unchanged |

Task 1.1 confirmed these tags on 2026-10-01; each index lists `linux/amd64` and `linux/arm64`. The Alpine `-dev` and
runtime tags are both `alpine3.23`. The guide's example pairs `-alpine3.22-dev` with an `-alpine3.23` runtime, but native
modules must match the libc they are built against, so both stages use the same Alpine release.

The digest pinned is the **multi-arch index digest**, so one `FROM` line serves both native runners. Each `FROM` line
also keeps the human-readable tag next to the digest. Node in these DHI releases is at `/usr/bin/node`, already on the
default `PATH`. The guide's `ENV PATH="/opt/nodejs/bin:$PATH"` describes an older layout and is not needed (task 1.2).
Build stages run `corepack enable`, so pnpm comes from the `packageManager` field as it does today. Final stages contain no `apk` or
`apt` upgrades: patching is Docker's job under the DHI SLA, as the guide says.

### D2. SPA images: the DHI nginx runtime with only `sh`, `envsubst` and `jq` copied in

This is the guide's documented pattern for nginx frontends: copy the minimum binaries from the nginx `-dev` variant
into the hardened nginx runtime, reset `ENTRYPOINT`, and run the start-up script. It keeps nginx, and therefore the
existing CSP, proxy and `resolver` behaviour, so the serving contract does not have to be re-implemented.

- **One allow-list for all three images: `/bin/sh`, `envsubst` and `jq`.** A `tools` stage `FROM` the nginx `-dev`
  image does three things:
  - `apt-get install`s `jq` and `gettext-base` if they are not already present;
  - stages those three binaries, plus exactly the shared libraries that `ldd` reports for them, under `/tools/` with
    their real paths;
  - creates the writable directories the runtime needs, owned by the DHI UID:GID.

  The final stage then takes everything with a single `COPY --from=tools /tools/ /`. That gives one auditable
  instruction, and no `RUN`.
- **The entrypoints are rewritten to use only those three tools and shell built-ins:**
  - wallet-web: the `awk` read of `/etc/resolv.conf` becomes a `while read` loop.
  - giano-example: the `sed`/`tr`/`grep` JSON scraping of `GIANO_CHAINS` (the `rpc_urls`, `chain_ids`, `json_string`
    and `js_string` helpers) becomes `jq`. The `jq` versions are more correct, because they parse JSON instead of
    pattern-matching it. `eval` for `GIANO_RPC_UPSTREAM_<id>` becomes `jq -n env`.
  - paymaster-admin already needs only `sh`, `jq`, `envsubst` and `printf`.

  The string escaping for `config.js` moves to `jq`'s `@json`, and `config.js.template` switches its string literals
  from single to double quotes, so `@json` output drops in directly. The `demo-deployment` scenario "Placeholder
  substitution only" is the regression test for this.
- **No `RUN` in the final stage.** Today's final-stage `RUN chmod/chown/rm/sed` is replaced as follows:
  - `COPY --chmod=0755` for the entrypoint;
  - `COPY --chown=65532:65532` for the bundle, plus the html root staged as `nginx`-owned in the `tools` stage. A
    `COPY` onto the base's existing root-owned directory takes the staged ownership; this was tested.
  - Nothing else. Task 1.2 found that the DHI nginx image already gives its runtime user (`nginx`, 65532) write access
    to `/etc/nginx/conf.d`, `/run/nginx` (where its `nginx.conf` puts the PID file) and `/var/cache/nginx`, and logs
    to stdout and stderr. The base `nginx.conf` is used unchanged, and the entrypoints keep their original paths:
    templates in `/etc/giano/`, the server block rendered to `/etc/nginx/conf.d/default.conf`.
- **The base already ships coreutils and gawk** (`cat`, `ls`, `tr`, `awk` and others), though no shell, no `sed`, no
  `grep`, no network client and no package manager. The allow-list governs what this repository **adds**. The
  entrypoints do not rely on the base utilities: the parity harness runs them with `PATH` holding only the three
  allowed tools.
- **Staging (`deploy/docker/stage-spa-tools.sh`).** The `tools` stage installs `dash`, `jq` and `gettext-base` and
  stages the following under `/staging`:
  - `dash` as `/usr/bin/sh` (in the merged-`/usr` runtime, `/bin` is a symlink to `usr/bin`);
  - `envsubst` and `jq`;
  - the two libraries `jq` links that the runtime lacks (`libjq.so.1`, `libonig.so.5`), under the real
    `/usr/lib/<triplet>` directory. glibc and the loader come from the runtime.
- **`ENTRYPOINT ["/entrypoint.sh"]`** is set explicitly, replacing the base image's entrypoint. The script ends in
  `exec nginx -g 'daemon off;'`, so nginx is PID 1 and receives the stop signal. `STOPSIGNAL` follows the base image.
- **The guide's caution is satisfied.** Its rule against copying `/bin/sh` concerns Node images. Its nginx section
  recommends exactly this pattern with "only the minimum required binaries". `docs/abip-compliance.md` records the
  allow-list as an applied guideline, not as an exception, and the `container-images` spec pins it.
- **Parity is the acceptance test.** Before the old entrypoints are changed, they are run on the host (CI runners have
  `sh`, `envsubst`, `jq`, `awk` and `sed`), with `exec nginx` stubbed out, against every environment fixture the
  repository uses: the e2e compose file, the infrastructure compose files and the Helm defaults. Their rendered files
  are committed as golden fixtures. A `node:test` suite runs the new entrypoints the same way and asserts semantically
  equal output.

*Alternatives considered:*
- *A shared Node server on the DHI Node runtime* (the previous draft of this design). It would be shell-free, but it
  re-implements nginx's serving, proxying and DNS re-resolution. It is several times the work, and the guide
  explicitly offers the nginx pattern instead.
- *njs inside the DHI nginx runtime.* `resolver` cannot take a variable, and per-chain `location` blocks would have to
  become njs handlers. It is not confirmed that the DHI image ships njs.
- *Copying `sed`, `awk`, `tr` and `grep` as well, and keeping the scripts as they are.* That doubles the tool surface to
  avoid a small rewrite, and the guide says to copy "only the minimum".

### D3. Node services: `.mjs` entrypoints, direct `node` start commands, and no shell anywhere in their runtime

- **`giano-wallet-api`.**
  - It already starts with `node dist/index.js` and migrates with `node dist/migrate.js`, and it handles `SIGTERM`
    itself.
  - The change: a `-dev` build stage, then `pnpm deploy --prod /out`, which is the guide's "prune" step. The runtime
    stage gets `COPY --chown`. `apk add curl` and `USER node` are removed.
  - The guide's TypeScript checklist (explicit `.js` import extensions, non-TS assets copied into `dist`,
    `NODE_ENV=production` behaviour) is verified by running the image in the e2e stack, not by inspection.
- **`giano-bundler`.**
  - In the `-dev` stage, `npm install --prefix /app @pimlico/alto@0.0.18`, replacing today's global install as root.
  - `services/bundler/entrypoint.mjs` ports the variable checks and the refusal to run with the Anvil key outside dev
    mode, keeping the wording. It then starts alto in-process (`import` of its CLI entry, with `process.argv` set) or,
    if that is not supported, with `spawn(process.execPath, [altoBin, …], { shell: false })` and signal forwarding.
  - Task 3.2 checks whether alto itself uses shell-mode `child_process` at runtime.
- **`giano-wallet-byo`.** `tini` is removed. `serve.mjs` adds a `SIGTERM` handler, and the entrypoint becomes
  `["node", "serve.mjs"]`. `node_modules` is copied with `--chown`. esbuild starts its native binary with
  `spawn`/`execFileSync` without a shell; task 3.4 confirms this.
- **`giano-contracts-deployer`.** This is the image the guide's shell rules change most.
  - **Problem.** `hardhat-foundry` shells out when the config loads. The runtime cannot have a shell, and per the guide
    it must not have `pnpm`, so the deployer cannot be started through `pnpm hh:deploy`.
  - **Approach: snapshot Foundry at build time, and deploy with a config that does not load the plugin.**
    - In the Debian `-dev` build stage, after `hh:compile`, write `forge config --json` and `forge remappings` to
      `foundry.snapshot.json`.
    - Add `hardhat.deploy.config.ts`. It contains the same solidity settings, networks and paths as
      `hardhat.config.ts`, imports `hardhat-toolbox` and `ignition-ethers` but not `hardhat-foundry`, and registers a
      small in-repo plugin. That plugin overrides the remapping subtask (`TASK_COMPILE_GET_REMAPPINGS`) to return the
      snapshot.
    - To avoid two configs drifting, the shared parts move to `hardhat.base.ts`, imported by both configs.
    - Because the compiled `artifacts/` and `cache/` are copied in, the deploy-time compile is a no-op, so `forge` is
      not needed at runtime and is no longer copied into the final stage.
  - **Guard.** Task 3.6 deploys from the image to the devnet and compares the addresses with the committed
    `addresses.ts` for chain 31337. The addresses must be identical. If they differ, the remapping override is wrong,
    and the change does not merge.
  - **`ts-node` → `tsx`, following the guide's checklist for Node 22 hardened images.**
    - `deployer-entrypoint.mjs` runs `gen:addresses` and the registry-JSON step with `node --require tsx/cjs`. It
      does not use `--import tsx`, which loads them as ES modules: the package is CommonJS and the scripts use
      `__dirname`.
    - Hardhat loads its TypeScript config through its own in-process `ts-node` hook, and that works on the DHI runtime
      (task 3.6). The fallback of transpiling the deploy config to JS was not needed.
    - Hardhat writes `~/.config/hardhat-nodejs` on start. The DHI Node image's user has `/home/node`, so no extra
      setup is needed. A UID with no home directory fails with `EACCES` at `/.config`.
    - `tsx` is already a workspace dependency (`^4.19.4`, in wallet-api and paymaster-sdk), so adding it to the
      contracts package brings in no new package.
  - **What reaches the runtime.** The `/repo` tree from the build stage, copied with `--chown=1000:1000`, as the old
    image copied it. `pnpm deploy` would pack the contracts package by its `files` list, which leaves out the Hardhat
    configs, `ignition/`, `scripts/` and `artifacts/`. Those are exactly the deploy job's runtime, and the deploy-time
    compile needs the sources and `cache/` to find the artefacts current. Build tooling (`python3`, `make`, `g++`,
    `git`, `forge`) is OS-level and stays in the build stage. `/out` is created owned by `node` in the build stage
    and copied over. There is no `RUN` in the runtime stage.
- **Init process.** None is added. Every Node process handles `SIGTERM` itself, which is the only reason `tini` was
  there.

### D4. Healthchecks

- **Node images.** Exec-form `node -e` fetch with a timeout:
  `["CMD","node","-e","fetch('http://127.0.0.1:8080/healthz',{signal:AbortSignal.timeout(2500)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]`.
  The bundler's probe is a `POST` of `eth_supportedEntryPoints`.
- **SPA images.** These have no HTTP client and should not get one. The check is
  `["CMD","/bin/sh","-c","test -s /run/nginx/nginx.pid && test -s <rendered config>"]`, using shell built-ins only.
  The HTTP checks stay with the ALB (`health_check_path = "/"`), Helm `httpGet` probes and the `curl` probes `e2e.yml`
  already runs from the host.
- **Compose files.** The `CMD-SHELL curl|wget` tests for images built from this repository change to these same forms.

### D5. Ownership, the runtime user and writable paths

Task 1.2 read the runtime users: the DHI Node images run as `node` (**1000:1000**, home `/home/node`), and DHI nginx
runs as `nginx` (**65532:65532**). Each `--chown` uses its image's numeric UID:GID, so it does not depend on
`/etc/passwd`. No final stage contains a `USER` line, because the DHI default is inherited. Directories written at start
(the html root for the SPAs, `/out` for the deployer) are created in a non-final stage and copied with ownership. nginx's
own writable paths come from the base. Nothing is `chmod`ed or `chown`ed by `RUN` in a final stage.

### D6. CI: login, base-signature verification, attestations, signing and the policy check

- **Login.** `docker/login-action` to `dhi.io`, using `secrets.DOCKERHUB_USERNAME` / `secrets.DOCKERHUB_TOKEN`, runs
  in `docker.yml` `build` (PRs included) and in `e2e.yml` before `compose up --build`. When the secret is empty (a fork
  PR, or before the secret is provisioned), the job emits `::notice::` and skips its build steps.
- **Verifying base images (guide: "CI/CD pipeline must also verify the signature of any pulled hardened base image").**
  Before `build-push-action`, a step lists the `dhi.io/...@sha256:` references in the matrix image's Dockerfile, using
  the same parser as the policy check (`check-dockerfiles.mjs --refs`), and verifies each one with Docker's
  documented DHI key, as confirmed in task 1.4:

  ```
  cosign verify <dhi.io/repo:tag@sha256:index> \
    --key https://registry.scout.docker.com/keyring/dhi/latest.pub \
    --insecure-ignore-tlog=true --experimental-oci11
  ```

  DHI signs the **index** and attaches the signature as an OCI 1.1 referrer, so `--experimental-oci11` is required;
  without it cosign reports "no signatures found". The signed claim names the exact index digest. `--insecure-ignore-tlog`
  is Docker's documented setting: DHI signatures are not written to the public Rekor log. Verification is offline, by
  key. `docker scout attest get --verify --skip-tlog` also works, but took about 4 minutes against cosign's seconds.

  A failure fails the job before any build. The verification needs the same `dhi.io` login, so it is skipped alongside
  the build when the secret is absent.
- **Attestations.** In `build`, `provenance: false` becomes `provenance: mode=min` plus `sbom: true`, matching ABIP-2's
  `--attest type=provenance,mode=min` and `--sbom=true`. `push-by-digest` pushes, per architecture, an index that
  holds the image and its attestation. `imagetools create` in `merge` combines the two per-architecture indexes and
  keeps the attestations.
- **Signing published images (guide: "All images pushed to the registry must be signed").**
  - In `merge`, after the GHCR list is created, `sigstore/cosign-installer` runs, followed by keyless
    `cosign sign --yes ghcr.io/…@<list digest>`. The signature uses the workflow's GitHub OIDC token; `id-token: write`
    is already granted.
  - The ECR copy is the same digest, so the signature is copied with it, using `cosign copy` or OCI 1.1 referrers
    (task 1.4 picks the mode). It verifies with the same identity.
  - PRs sign nothing.
- **ECR budget.** Each published commit was 3 ECR images (one index plus two platform manifests). It becomes about 6:
  two attestation manifests and one signature are added. `ecr_lifecycle_image_count` is raised from 10 to 30 in each
  environment, which keeps retention at about 5 commits, no worse than today's 3. Task 9.4 checks the real count with
  `aws ecr describe-images`. The edit is made in this change; `terraform apply` is deferred.
- **Policy check.** `scripts/check-dockerfiles.mjs` has no dependencies and reads the image list from `docker.yml`. For
  each Dockerfile it parses the stages and asserts the `container-images` rules:
  - the `dhi.io` host and an `@sha256:` digest;
  - `-dev` everywhere except the final stage;
  - only the allowed instructions in the final stage, with no `RUN` and no `USER`;
  - no community bases.

  The exception list comes from a fenced, machine-readable block in `docs/abip-compliance.md`. The check runs in
  `ci.yml` without registry access, so it runs on fork PRs as well.

### D7. Digest pinning and refresh

All pins land in this change. ABIP-2's "MAY defer during migration" applies only while the branch is open; the PR does
not merge with an unpinned `FROM`, and the policy check enforces this. The refresh procedure is recorded in
`docs/abip-compliance.md`:
1. resolve the index digest with `docker buildx imagetools inspect`;
2. update every Dockerfile that uses that tag;
3. let CI verify the signature;
4. run e2e.

Automation is a follow-up issue.

### D8. The giano-devnet exception

The Foundry image (`ghcr.io/foundry-rs/foundry`) has no DHI equivalent, and devnet is a local and CI chain that is never
deployed to AWS (it is GHCR-only in `docker.yml`). It stays digest-pinned to the same Foundry version as
`determinism.yml` and the deployer's build-stage `forge`. `docs/abip-compliance.md` records the following:
- the reason;
- the mitigations: digest pin, no ECR repository, never deployed to a non-local environment;
- the tracking issue: "Revisit giano-devnet base when a hardened Foundry/anvil image exists".

The deployer's build-stage `COPY --from=<foundry digest>` of `forge` is covered by the same entry. After D3, `forge` no
longer reaches any final stage.

## Risks / Trade-offs

- **The SPA images keep a shell.** It is a minimal one: `sh`, `envsubst` and `jq`, with no coreutils, network tools or
  package manager. → This is the guide's sanctioned pattern, it is pinned by the "SPA images carry only the minimal
  start-up tools" requirement, and it is checked by inspecting the image (task 8.3).
- **The deploy config could drift from the compile config, or the remapping override could be wrong, which would move
  the CREATE2 addresses.** → The shared `hardhat.base.ts` prevents drift, and the address-equality check on the devnet
  (task 3.6) is a merge gate.
- **Alto or esbuild may use shell-mode `child_process` at runtime.** → Tasks 3.2 and 3.4 check this by running the
  image. If either does, the fix is a non-shell `spawn` wrapper. If neither works, it is raised as a blocking question.
  It is not worked around with a shell.
- **A DHI base ships utilities this repository did not choose** (coreutils and gawk in nginx). → They come from Docker
  under its SLA. The allow-list governs only what is added, and the entrypoints are tested without them.
- **CI image builds break until the Docker Hub secret exists.** → Builds skip with a notice instead of failing (D6).
  The branch must not merge until `docker.yml` and `e2e.yml` are green on the PR. Otherwise `main` would publish
  nothing.
- **The estimate.** With the nginx pattern from the guide, the SPA work shrinks to rewriting the entrypoints. The
  deployer (D3) is now the largest single item. It is close to the 1-day estimate but probably exceeds it.

## Migration Plan

1. Develop and verify locally after `docker login dhi.io`: build all eight images, run the parity tests and the
   deployer address check, and run `docker compose -f deploy/docker-compose.e2e.yml up --build --wait` plus the
   Playwright suite.
2. Open the PR. `ci.yml`, including the policy check, runs on every PR. `docker.yml` and `e2e.yml` skip their builds
   with a notice until the secret exists.
3. **Deferred group, callable later:**
   - the DevOps request for `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`;
   - get the PR's `docker.yml` and `e2e.yml` green;
   - merge;
   - `terraform apply` for the ECR budget, applied before the first attested publish reaches ECR;
   - first publish, then verify the SBOM, signature and digest equality;
   - roll out to dev ECS through `image_tag`, then smoke-test.
4. **Rollback:** the previous images stay in GHCR and ECR. Rolling back is `terraform apply -var image_tag=<previous
   sha>`. The environment contract is unchanged, so no task definition changes are needed.

## Open Questions

- Which Docker Hub account owns the CI token: an existing AB org account or a new service account? This is decided in
  the DevOps request; only the secret names reach the code.
- None from task 1: the tags, digests, users, nginx paths and verification command are recorded above.
