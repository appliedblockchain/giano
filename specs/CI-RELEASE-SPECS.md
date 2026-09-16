# Giano — CI build, push and tag configuration

This document is the **how** for H2 (*CI build, push and tag configuration*, 3 SP), whose **what**
is the five requirements R1–R5 reproduced in [§2](#2-the-requirements). It specifies the release
pipeline: which packages are published, where, at what version, under what guarantee of
immutability, and how containers reach GHCR and ECR.

Everything asserted about the current state in [§3](#3-current-state-verified) was read out of this
repository, its workflow-run history, or the registries themselves on 2026-09-15; each claim carries
its evidence. [§11](#11-traceability) maps every requirement to the section that satisfies it.

Status: **specified and implemented.** [§10](#10-risks-and-open-items) lists the items still open;
none of them blocks the pipeline.

---

## Contents

1. [Scope and decisions](#1-scope-and-decisions)
2. [The requirements](#2-the-requirements)
3. [Current state, verified](#3-current-state-verified)
4. [R1 — the publishable set](#4-r1--the-publishable-set)
5. [R2 — every merge publishes at the correct version](#5-r2--every-merge-publishes-at-the-correct-version)
6. [R3 — a published version is never overridden](#6-r3--a-published-version-is-never-overridden)
7. [R4 / R5 — containers, ECR and GHCR](#7-r4--r5--containers-ecr-and-ghcr)
8. [Consumption](#8-consumption)
9. [Acceptance](#9-acceptance)
10. [Risks and open items](#10-risks-and-open-items)
11. [Traceability](#11-traceability)

---

## 1. Scope and decisions

### 1.1 What H2 actually delivers

The container half of H2 is built. `.github/workflows/docker.yml` builds all eight images on native
runners per architecture, publishes manifest lists to GHCR, and copies six of them into ECR by
digest. R4 and R5 are therefore **verification work**, not implementation work — [§7](#7-r4--r5--containers-ecr-and-ghcr)
records the verification and the two discrepancies it turned up.

The npm half is the work. `.github/workflows/release.yml` ran green on every merge to `main`
without ever putting a package on `npm.pkg.github.com`: it maintained a version pull request, and
publishing waited on that pull request being merged. H2 replaces it with a pipeline that publishes a
snapshot on every merge and the stable version on a `v*` tag.

Nine deliverables, D1–D8 plus D1a, stand between "the workflow runs" and "R1–R3 hold".

### 1.2 Decisions taken in this spec

| # | Decision | Why |
| --- | --- | --- |
| **D-a** | Every merge to `main` that releases something publishes a **snapshot**, `3.0.0-main-<sha>`. A `v*` tag publishes the **stable** version. | R2 read literally: the merge itself is what puts an artifact on the registry. Each commit gets a distinct immutable version, so nothing is overridden (R3) and no stable version number is burned — the stable line advances only when a human cuts a release. The snapshot names the line it is heading for, so `^3.0.0-main-…` also matches the eventual `3.0.0`, and an integrator tracking `main` converges onto the real release rather than away from it. [§5.1](#51-what-every-merge-to-main-means). |
| **D-a1** | Snapshot versions come from `snapshot.useCalculatedVersion: true` with `prereleaseTemplate: "{tag}-{commit}"`. | `{commit}` rather than `{datetime}`: a workflow re-run then computes the *identical* version, which is what keeps the re-run idempotent under R3 ([§6.1](#61-a-workflow-re-run-at-the-same-commit--closed)). A timestamp would publish a fresh version on every re-run. |
| **D-a2** | Inter-package dependencies are declared `workspace:*`. | pnpm rewrites it to the sibling's **exact** version at pack time, so a snapshot tarball names one specific sibling build. A caret range over a prerelease line is satisfiable by *other* snapshots, which would let an install assemble six fixed-group packages from more than one commit. [§4.3](#43-what-each-package-ships). |
| **D-b** | The publishable set stays **explicitly enumerated**, and CI asserts the enumeration. Never derived from a directory glob. | Publishing must be an intentional act. Under R3 the two failure modes are not symmetrical: a package that should have shipped and did not is fixed in the next release, while one published by accident is permanent, at a version that can never be reused. A glob makes creating a directory sufficient to publish; a list plus an assertion makes it require a deliberate edit that a reviewer sees. [§4.2](#42-the-set-is-enumerated-and-the-enumeration-is-enforced). |
| **D-c** | Immutability is the **registry's** guarantee, asserted in CI — not a convention. | GitHub Packages rejects a re-publish over an existing version with `E403`; ECR repositories are `IMMUTABLE`. Both are already true. What is missing is the assertion that they stay true. [§6](#6-r3--a-published-version-is-never-overridden). |
| **D-d** | A stable release is cut by pushing a `v*` tag, not by promoting a snapshot. | npm has no promote operation: `3.0.0-main-<sha>` and `3.0.0` are two distinct immutable versions, so the stable number can only come from a second publish of the same tree, and something has to trigger it. A tag is a reviewable, assertable trigger that `docker.yml` already listens to, so one push ships packages and images at one Giano version. |
| **D-e** | The version bump reaches `main` through an ordinary human-authored pull request, never a push from CI. | A commit pushed to `main` by a workflow carries no check runs, and D5's required status checks block direct pushes as well as merges — so a CI-side write-back would need an admin PAT or an App in the ruleset bypass list. A release pull request draws review and CI like any other change, needs no privileged credential, and keeps the tag→version mapping assertable. [§5.5](#55-d5--main-requires-green-checks). |
| **D-f** | The tag path re-runs CI and Determinism, and additionally asserts that the commit is an ancestor of `main` and that the six `package.json` versions match the tag. | The tagged commit already passed the gate on its way into `main`, so this re-proves a green tree at ~4m25s — on a job that runs a handful of times a year. The alternative, reading the verdict out of the run history, expires: from 2026-10-01 GitHub retires check, run and status records on the Actions retention setting, 90 days at most on a public repository, so a patch cut from an older commit would read as one that never passed. Ancestry is not redundant with the gate — the gate says the tree is green, ancestry says it came from `main`. [§5.4](#54-d4--the-release-cannot-publish-what-ci-has-not-checked). |

### 1.3 Out of scope

Staging and production ECR namespaces (`giano-stg/*`, `giano-prd/*`), container signing/attestation,
and the rollout workflow (`deploy.yml`, which reads `infra/versions.json` and is specified in
[`specs/INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §15).

**`infra/iac/` is devops territory and this spec changes nothing in it.** Terraform is read here as
evidence — ECR repository names, tag immutability, lifecycle counts, the OIDC role's trusted refs —
and where a reading turns up something worth changing, it is raised as an open item addressed to
whoever owns that module, never as an H2 deliverable. **O-6** is the one such item.

Publishing Giano packages **to npmjs.org** is out of scope. R1 names `npm.pkg.github.com` and this
spec builds that: the call on **O-4** was to implement R1 as written, integrator token and all, with
[§8.2](#82-a-public-package-that-still-needs-a-token) recording what that costs. The one npmjs action
this spec does propose is deprecating the stale `giano-contracts` versions already there
([§8.1](#81-the-scope-collision)).

---

## 2. The requirements

Reproduced verbatim from the H2 page so this document stands alone.

**R1 — Every publishable NPM package is published to the GitHub registry** (`npm.pkg.github.com`),
under the `@appliedblockchain` scope. Six packages, exhaustively:

| # | Package | Version at time of writing |
| --- | --- | --- |
| 1 | `@appliedblockchain/giano-contracts` | `2.1.0` |
| 2 | `@appliedblockchain/giano-wallet-transport` | `0.1.0` |
| 3 | `@appliedblockchain/giano-wallet-core` | `0.1.0` |
| 4 | `@appliedblockchain/giano-connector` | `0.1.0` |
| 5 | `@appliedblockchain/giano-wallet-kit` | `0.1.0` |
| 6 | `@appliedblockchain/giano-paymaster-sdk` | `0.1.0` |

Five workspace packages are `private: true` and must stay unpublished: `giano-wallet-api`,
`giano-wallet-web`, `giano-paymaster-admin`, `giano-example`, `giano-e2e`.

**R2 — Every merge to `main` publishes a package at the correct version.** No manual publish step.

**R3 — A published version can never be overridden.** Not by a re-run, not by a rebuilt artifact at
the same version.

**R4 — Containers are published to AWS ECR.** Eight images build; six have ECR repositories:

| # | Image | Dockerfile | ECR repository |
| --- | --- | --- | --- |
| 1 | `giano-wallet-api` | `services/wallet-api/Dockerfile` | `giano-dev/wallet-api` |
| 2 | `giano-wallet-web` | `services/wallet-web/Dockerfile` | `giano-dev/wallet-web` |
| 3 | `giano-paymaster-admin` | `services/paymaster-admin/Dockerfile` | `giano-dev/paymaster-admin` |
| 4 | `giano-example` | `services/custom-example/Dockerfile` | `giano-dev/example` |
| 5 | `giano-wallet-byo` | `e2e/wallet-byo/Dockerfile` | `giano-dev/wallet-byo` |
| 6 | `giano-bundler` | `services/bundler/Dockerfile` | `giano-dev/bundler` |
| 7 | `giano-devnet` | `services/devnet/Dockerfile` | — none |
| 8 | `giano-contracts-deployer` | `packages/contracts/Dockerfile.deployer` | — none |

**R5 — The GHCR container push is retained.** All eight images continue to be pushed there,
including the two with no ECR repository. ECR does not replace it.

---

## 3. Current state, verified

| Claim | Verdict | Evidence |
| --- | --- | --- |
| All six publishable packages carry `publishConfig.registry = https://npm.pkg.github.com` | ✅ | `packages/*/package.json` |
| All six also carry `publishConfig.access = restricted` — which GitHub Packages ignores for visibility | ⚠️ inert | `packages/*/package.json`, `.changeset/config.json`; see [§4.1](#visibility--the-six-packages-will-be-public) |
| `appliedblockchain/giano` is a **public** repository, so the six packages will be **public** | ⚠️ | `gh repo view --json visibility` → `PUBLIC` |
| A public GitHub Packages npm package can be installed anonymously | ❌ **No** | `npm.pkg.github.com` has no anonymous read path, unlike GHCR; [§8.2](#82-a-public-package-that-still-needs-a-token) |
| All six carry a `repository` object with `directory` — required by GitHub Packages to bind the package to the repo | ✅ | `packages/*/package.json` |
| All six ship only `dist` (contracts also ships `.sol` sources and the generated TS) via `files` | ✅ | `packages/*/package.json` |
| The five private packages are `private: true` | ✅ | `services/{wallet-api,wallet-web,paymaster-admin,custom-example}/package.json`, `e2e/package.json` |
| `packages/*` contains exactly the six publishable packages; nothing publishable lives elsewhere | ✅ | `pnpm-workspace.yaml` (`services/*`, `packages/*`, `e2e`) — 12 workspace projects, of which 6 are `packages/*` |
| `release.yml` runs on every push to `main` and succeeds | ✅ | 10 consecutive `success` runs, 2026-09-07 → 2026-09-11 |
| Anything has been published to `npm.pkg.github.com` | ❌ **No** | The only publish path was `changesets/action`'s publish branch, which runs only when no changesets are pending; 11 are pending |
| `ci.yml` gates the publish | ❌ **No** | `ci.yml` and `release.yml` both trigger on `push: branches: [main]` and run **concurrently**, so a green publish over a red CI is reachable |
| `main` is protected | ✅ | `gh api .../branches/main` → `protected: true`, a classic rule (`rulesets` and `rules/branches/main` are both `[]`) |
| That protection requires any status check | ❌ **No** | same call → `required_status_checks: {checks: [], contexts: [], enforcement_level: "off"}`; [§5.5](#55-d5--main-requires-green-checks) |
| `@appliedblockchain/giano-contracts` already exists on **npmjs.org** | ⚠️ **Yes**, `1.0.0`–`2.0.1`, `latest = 2.0.1`, public | `npm view … --registry=https://registry.npmjs.org`. Published before `publishConfig` was introduced — see git tags `contracts-v1.0.1`…`contracts-v2.0.1` |
| The other five exist on npmjs.org | ✅ No — all `E404` | same |
| `docker.yml` builds all eight images and pushes all eight to GHCR | ✅ | `.github/workflows/docker.yml`, `setup` job image list; all eight Dockerfiles exist at the stated paths |
| `docker.yml` copies the six ECR-backed images to ECR by digest, on `refs/heads/main` only | ✅ | `docker.yml` `merge` job; gated on `matrix.image.ecr != '' && github.ref == 'refs/heads/main'` |
| ECR repository names match R4 | ✅ | `infra/iac/ecr.vars.tf` `ecr_repos = ["wallet-api", "wallet-web", "paymaster-admin", "example", "wallet-byo", "bundler"]` |
| ECR repositories are `IMMUTABLE` in every environment | ✅ | `infra/iac/ecr.vars.tf` `ecr_image_tag_mutability` |

### 3.1 What the pending changesets resolve to

As the configuration stands before D1, `pnpm changeset status` resolves the 11 pending changesets to
eleven version changes, of which six matter:

| Package | Old | New | Note |
| --- | --- | --- | --- |
| `giano-contracts` | 2.1.0 | **3.0.0** | fixed group |
| `giano-wallet-core` | 0.1.0 | **3.0.0** | fixed group — jumps from 0.1.0 |
| `giano-wallet-transport` | 0.1.0 | **3.0.0** | fixed group |
| `giano-connector` | 0.1.0 | **3.0.0** | fixed group |
| `giano-paymaster-sdk` | 0.1.0 | **3.0.0** | fixed group |
| `giano-wallet-kit` | 0.1.0 | **1.0.0** | ⚠️ **not in the fixed group** |
| `giano-wallet-api` | 0.1.0 | 0.2.0 | private |
| `giano-wallet-web` | 0.1.0 | 1.0.0 | private |
| `giano-paymaster-admin` | 0.1.0 | 0.1.1 | private |
| `giano-example` | 0.1.0 | 0.1.0 | private, and `ignore`d |
| `giano-e2e` | 0.0.0 | 0.0.0 | private |

The 0.1.0 → 3.0.0 jump is intended: `.changeset/phase-4-version-alignment.md` states that fixed-mode
versioning ships all Giano packages at one version. `giano-wallet-kit` landing at 1.0.0 is **not** —
it is missing from `fixed` in `.changeset/config.json`. The four private packages that take a bump
they never publish make a reviewer read eleven version changes when six matter. Both are D1
([§5.2](#52-d1--one-fixed-group-identical-to-the-publishable-set)).

With D1 applied, the same command resolves exactly six releases, all at `3.0.0`, and the fixed group
is identical to the publishable set.

---

## 4. R1 — the publishable set

### 4.1 Registry, scope and auth

Publication target is `https://npm.pkg.github.com`, scope `@appliedblockchain`. Two mechanisms carry
that, and they must not be confused:

- **Routing** comes from each package's own `publishConfig.registry`. Changesets reads it —
  `getCorrectRegistry()` prefers `publishConfig["@scope:registry"]`, then `publishConfig.registry` —
  and passes it as `--registry=` to both the `npm info` pre-check and `pnpm publish`. No scope
  routing belongs in CI's `.npmrc`; see [§8.1](#81-the-scope-collision).
- **Auth** comes from CI's `$HOME/.npmrc`, host-scoped only:
  `//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}`. This is what `release.yml` already writes, and
  it is correct as written. `GITHUB_TOKEN` with `permissions: packages: write` can create and push
  packages owned by this repository; no PAT is needed for the publish itself.

GitHub Packages requires an authenticated read as well as an authenticated write, so the same
`.npmrc` is what makes the `npm info` pre-check work. Without it, every package would look
unpublished.

#### Visibility — the six packages will be public

`appliedblockchain/giano` is a **public** repository (`gh repo view --json visibility` → `PUBLIC`,
which is also why `docker.yml` can use free native arm64 runners). An npm package on GitHub Packages
takes its visibility from the repository it is linked to, and all six link to this one through their
`repository` field. **The six packages will therefore be public packages.**

The `access: "restricted"` carried by all six `publishConfig` blocks, and by `.changeset/config.json`,
does not change that. `access` is an npmjs concept — it is what distinguishes a free public scoped
package from a paid private one on `registry.npmjs.org`. GitHub Packages accepts the flag on publish
and ignores it for visibility, which is governed by the repository and by each package's own settings
page. The field is inert here; it is kept only because removing it changes nothing and `npm publish`
wants *some* value. `specs/DEVELOPER-GUIDE.md` §2.1 describes the packages as "`access: restricted`"
in a way that reads as an access-control statement. It is not one, and that line needs rewording.

What survives is the part that is genuinely GitHub Packages' behaviour, and it is unrelated to
visibility: **`npm.pkg.github.com` requires a token on every read, public packages included.** Unlike
GHCR, which serves public images anonymously, the npm registry has no anonymous read path. So a
consumer of these six packages needs a token whether or not the packages are public — see
[§8.2](#82-a-public-package-that-still-needs-a-token).

### 4.2 The set is enumerated, and the enumeration is enforced

`release.yml` names the six packages explicitly, in dependency order, and keeps doing so (D-b).

That list controls what is **built**, not what is published. `changeset publish` walks the whole
workspace and publishes everything that is not `private: true`, so the two sets are independent
today. A seventh package added under `packages/` without a `private` flag is published at its first
release having never been built: an empty `dist`, at a permanent version, in a registry that will not
let it be replaced. The list needs an assertion behind it.

**D2.** Pin the publishable set in CI, in the `packages` job of `ci.yml`:

```yaml
      - name: The publishable set is exactly the six R1 packages
        # `changeset publish` publishes whatever is not `private: true`; release.yml's build list
        # only controls what gets BUILT. This ties the two together, so a new workspace package is
        # unpublishable until someone edits this list on purpose, and a package that loses
        # `private: true` by accident fails here rather than at a permanent version in the registry.
        # The YAML literal block strips its own indent, so the names reach the shell flush-left.
        run: |
          expected="@appliedblockchain/giano-connector
          @appliedblockchain/giano-contracts
          @appliedblockchain/giano-paymaster-sdk
          @appliedblockchain/giano-wallet-core
          @appliedblockchain/giano-wallet-kit
          @appliedblockchain/giano-wallet-transport"
          # the workspace root is itself `private: true`, so it drops out with the other five
          actual=$(pnpm ls -r --depth -1 --json | jq -r '.[] | select(.private != true) | .name')
          diff <(sort <<< "$expected") <(sort <<< "$actual")
```

A developer who adds a package and sees this go red has to decide whether it is meant to ship.
Marking it `private: true` is one answer; adding it here *and* to `release.yml`'s build list is the
other. Neither happens by omission.

> If the two lists drift in practice, move the six names into one checked-in file that `release.yml`
> reads to drive the build and `ci.yml` reads to drive this check. Not proposed here: two short lists
> that both fail loudly are easier to review than a third file neither job mentions by name.

### 4.3 What each package ships

Unchanged by H2, recorded because R1's "published" means "published usably":

| Package | `files` | `prepublishOnly` | Workspace deps |
| --- | --- | --- | --- |
| `giano-contracts` | `dist`, `src/**/*.sol`, `index.ts`, `generated.ts`, `addresses.ts`, `canonical.ts`, `chains.ts`, `address-overrides.json`, `remappings.txt` | `pnpm build:ts` | — |
| `giano-wallet-transport` | `dist` | `pnpm build` | — |
| `giano-wallet-core` | `dist` | `pnpm build` | contracts |
| `giano-connector` | `dist` | `pnpm build` | wallet-transport |
| `giano-wallet-kit` | `dist` | `pnpm build` | contracts, wallet-core, wallet-transport |
| `giano-paymaster-sdk` | `dist` | `pnpm build` | contracts |

Every workspace dependency is declared **`workspace:*`** (D-a2). `pnpm publish` rewrites that to the
sibling's exact version at pack time — `workspace:*` → `3.0.0`, and in a snapshot build
`workspace:*` → `3.0.0-main-<sha>` — so a published tarball names one specific sibling build rather
than a range over several.

The distinction is what makes snapshots safe to install. Under `workspace:^` the snapshot tarball
would carry `^3.0.0-main-<sha>`; semver orders prereleases lexically within a version, so that range
also admits *other* `3.0.0-main-…` snapshots, and an install could assemble `giano-wallet-kit` from
one commit with a `giano-wallet-core` from another. Six packages in a fixed group are one artifact
split six ways, and an exact pin is what keeps them one artifact.

Two facts this rests on, both verified against the versions pinned here:

- `@changesets/apply-release-plan@7.1.1` leaves a bare `workspace:*` untouched when it rewrites
  versions, so a `changeset version` run does not turn it back into a range.
- `pnpm pack` of a snapshot-versioned `giano-wallet-kit` emits `"@appliedblockchain/giano-contracts":
  "3.0.0-main-<sha>"` — the concrete version, no caret.

This is also why `changeset publish` must run through pnpm, which it does: Changesets 2.31.1's
`getPublishTool()` detects pnpm and spawns `pnpm publish --no-git-checks`.

---

## 5. R2 — every merge publishes at the correct version

### 5.1 What "every merge to `main`" means

Every merge that changes a publishable package publishes one, as a snapshot, once CI and Determinism
are green. Cutting a stable release is a separate, deliberate act that ends in a tag.

```
  PR with a changeset ──merge──▶ main
                                  └─ release.yml
                                     ├─ ci.yml + determinism.yml as a gate (~4m25s)
                                     └─ changeset version --snapshot main
                                        changeset publish --tag main --no-git-tag
                                        └─ 3.0.0-main-<sha> ×6, dist-tag `main`

  cutting a release (human, local):
    pnpm changeset version    → bumps all six to 3.0.0, writes CHANGELOGs,
                                consumes the changesets
    commit on a branch, open a PR, normal review + required checks, merge

  git push origin v3.0.0 ────▶ release.yml
                                 ├─ assert the tag is on main and names the
                                 │  version in package.json
                                 └─ changeset publish  → 3.0.0 ×6, dist-tag `latest`
                                    git push --tags    → six per-package tags
```

R2's "no manual publish step" holds in the strict reading: the merge itself puts an artifact on the
registry, with no human running `npm publish`, setting a version by hand, or dispatching a workflow.

Two properties worth stating plainly:

- **"Every merge publishes" holds for every merge that changes a publishable package**, because D3
  forces such a pull request to carry a changeset. A merge that touches nothing publishable publishes
  nothing, and the snapshot job exits zero after saying so.
- `docker.yml` already triggers on `tags: ['v*']`, so a `v3.0.0` tag builds and pushes images tagged
  `v3.0.0` alongside the six packages. One Giano version across both halves of the release.

#### Why the stable bump lands through a pull request

Promotion cannot be literal. npm has no rename: `3.0.0-main-<sha>` and `3.0.0` are two distinct
immutable versions, so promoting a snapshot means re-publishing the same tree under the stable
number — and that number has to be written back to `main`, or the next release recomputes `3.0.0`
and collides with what is already on the registry.

A commit pushed to `main` by a workflow carries no check runs, and D5's required status checks block
direct pushes as well as merges, so a CI-side write-back would need an admin PAT or a GitHub App in
the ruleset bypass list — a credential to own and rotate, bought for one commit a human is going to
read anyway. A human-authored release pull request draws review and CI like any other change, needs
no privileged credential, and leaves a merge commit the tag job can assert against.

### 5.2 D1 — one fixed group, identical to the publishable set

`.changeset/config.json` gains the sixth name in `fixed`, the four remaining private packages in
`ignore`, and the `snapshot` block:

```json
  "fixed": [
    [
      "@appliedblockchain/giano-contracts",
      "@appliedblockchain/giano-wallet-core",
      "@appliedblockchain/giano-wallet-transport",
      "@appliedblockchain/giano-connector",
      "@appliedblockchain/giano-wallet-kit",
      "@appliedblockchain/giano-paymaster-sdk"
    ]
  ],
  "snapshot": {
    "useCalculatedVersion": true,
    "prereleaseTemplate": "{tag}-{commit}"
  },
  "ignore": [
    "@appliedblockchain/giano-example",
    "@appliedblockchain/giano-wallet-api",
    "@appliedblockchain/giano-wallet-web",
    "@appliedblockchain/giano-paymaster-admin",
    "@appliedblockchain/giano-e2e"
  ]
```

With this the pending release resolves all six to `3.0.0` instead of five at `3.0.0` and wallet-kit
at `1.0.0`, and the release diff shows six version changes instead of eleven. The fixed group is then
*identical* to the publishable set, which is the invariant worth having: one Giano version, published
six times.

`useCalculatedVersion` is what makes the snapshot base `3.0.0` — the version the pending changesets
resolve to — rather than the current `0.1.0`. Without it a snapshot would be
`0.0.0-main-<sha>`, which sorts below everything and tells an integrator nothing about where the
line is heading.

The private packages are ignored rather than versioned because their versions are cosmetic: images
are tagged by commit SHA, never by package version (`infra/versions.json`,
[`specs/INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §15.1).

#### The constraint `ignore` introduces

Changesets refuses a changeset that names **both** an ignored package and a released one — `Found
mixed changeset`, and `changeset version` fails outright. Going forward, a change spanning
`packages/wallet-core` and `services/wallet-api` needs two changeset files, not one.

The existing changesets were checked against this before `ignore` grew: none names both a published
and a soon-ignored package. The two private-only files (`wallet-api-relays.md`,
`wallet-web-relay-only.md`) are still consumed and deleted normally, because `getRelevantChangesets`
errors on mixed changesets only.

### 5.3 D3 — a merge that should publish, but carries no changeset, fails

Nothing today stops a pull request that changes `packages/wallet-core/src` from merging without a
changeset. It merges, publishes a snapshot at whatever version the *other* pending changesets imply,
and ships inside whatever release happens next — silently, at a version that does not describe it.
That is the practical way R2 breaks.

The `packages` job's checkout gains full history, because `changeset status --since` resolves
`origin/<base>` and the default shallow clone has no such ref:

```yaml
      - uses: actions/checkout@v7
        with:
          # deliberately NO submodules: proves a fresh clone builds the TS surface.
          # Full history so `origin/<base>` exists for `changeset status --since`.
          fetch-depth: 0
```

and the job gains the gate:

```yaml
      - name: A change to a publishable package carries a changeset
        if: github.event_name == 'pull_request'
        env:
          BASE_REF: ${{ github.base_ref }}
        run: |
          # A release PR touches only package.json and CHANGELOG.md under packages/ — its whole job
          # is to CONSUME changesets, so requiring one of it would make it unmergeable under the
          # required status checks on main.
          if git diff --quiet "origin/$BASE_REF...HEAD" -- packages/ \
               ':(exclude)packages/*/package.json' ':(exclude)packages/*/CHANGELOG.md'; then
            echo "no publishable source touched — no changeset required"
            exit 0
          fi
          pnpm changeset status --since="origin/$BASE_REF"
```

`changeset status --since` exits non-zero when changed packages have no changeset. The `git diff`
guard keeps infra-only and docs-only pull requests green. An intentional no-release change — a
comment, a test — is unblocked the documented way, `pnpm changeset --empty`.

The two pathspec exclusions are what stop this deadlocking with D5. A release pull request consumes
every changeset and touches nothing under `packages/` except `package.json` and `CHANGELOG.md`;
without the exclusions this step would demand a changeset of the one pull request whose purpose is to
have none, and required checks would make it permanently unmergeable.

`BASE_REF` goes through `env:` rather than a raw `${{ }}` interpolation, so a branch name never
reaches the shell's parser.

### 5.4 D4 — the release cannot publish what CI has not checked

`release.yml` and `ci.yml` both trigger on `push: branches: [main]` and run **concurrently**.
`release.yml` builds the six packages, so a compile break stops it — but no unit test, no OpenAPI
drift check and no `addresses.ts` drift check gates publication. A green publish over a red CI is
reachable today.

Make `ci.yml` callable, and let the release be the only thing that runs it on `main`:

```yaml
# .github/workflows/ci.yml
on:
  pull_request:
  workflow_call:

# Without this a called workflow inherits the CALLER's token — every job here would then run
# with release.yml's `packages: write`. Nothing below needs more than read: no step reads a
# secret, all six git submodules are public, and setup-node's pnpm cache authenticates with
# ACTIONS_RUNTIME_TOKEN rather than GITHUB_TOKEN.
permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  # The `github` context inside a called workflow is the caller's, so this is `push` when CI
  # runs as the release gate and `pull_request` when it runs standalone: a merge's gate run is
  # never cancelled out from under the publish that needs it.
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

`permissions: contents: read` is not cosmetic. A called workflow that declares no permissions block
inherits the caller's token, so without it every CI job would run holding `release.yml`'s
`packages: write`.

`determinism.yml` takes the same treatment, with two differences. Its `pull_request` path filter
stays verbatim; only the unconditional `push: branches: [main]` is replaced by `workflow_call`. And
its concurrency group is prefixed `determinism-`, which must differ from `release-` so the caller can
never queue behind its own callee. A `paths:` filter lives under `pull_request:` only and is ignored
by `workflow_call`, so both determinism jobs run on every release — correct for a gate, and the
reason release wall-clock goes from ~1m16s to ~4m25s.

```yaml
# .github/workflows/release.yml
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  ci:
    name: CI
    uses: ./.github/workflows/ci.yml

  determinism:
    name: Determinism
    uses: ./.github/workflows/determinism.yml

  snapshot:
    name: Publish snapshot
    if: github.ref == 'refs/heads/main'
    needs: [ci, determinism]
    # …

  release:
    name: Publish release
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [ci, determinism]
    # …
```

One run of each per ref, and neither publish can start until both are green. Neither
needs `secrets: inherit` — their jobs use only `actions/checkout`, pnpm, Node and Foundry.

#### The tag path re-runs the gate

A `v*` tag points at a commit that already passed CI and Determinism on its way into `main` — same
SHA, same tree — so the gate jobs lose their `if: github.ref == 'refs/heads/main'` and run on both
paths, and `release` picks up the same `needs: [ci, determinism]` the snapshot job has:

```yaml
jobs:
  ci:
    name: CI
    uses: ./.github/workflows/ci.yml

  determinism:
    name: Determinism
    uses: ./.github/workflows/determinism.yml

  release:
    name: Publish release
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [ci, determinism]
```

This does re-prove a tree that was already green, at ~4m25s on a job that runs a handful of times a
year. What it buys is that the proof is produced rather than looked up.

The alternative is to assert the gate *already* passed, by asking the API whether a successful `main`
run of `release.yml` exists at this SHA — one query, about a second, and no dependence on `main`
rejecting red commits, which is D5 and not yet configured. That version was written and then
withdrawn, because its evidence expires. From **2026-10-01** GitHub governs checks, workflow runs and
statuses by the Actions retention setting rather than keeping them 400+ days; on a public repository
that setting caps at 90 days. A patch cut from an older commit — a maintenance line, a release
deferred past a quarter — would then find no run record and read as a commit that never passed, and
the failure mode is a release blocked by bookkeeping rather than by anything about the code. A gate
that runs cannot expire.

It also removes a dependency in the wrong direction. Reading the verdict makes the tag path correct
only while the run history is intact; re-running makes it correct on its own terms, and leaves D5 as
what it should be — the thing that moves a failure *before* the merge, where a human is still
looking at it, rather than the thing a publish quietly rests on.

What the gate does **not** establish is where the tree came from. It would pass just as happily on a
tag pushed at a feature branch, or at a commit that left `main` on a force-push. Two assertions in
the release job cover the rest:

```yaml
      - name: This tag is on main, and names the version it publishes
        run: |
          git fetch --no-tags origin main
          git merge-base --is-ancestor "$GITHUB_SHA" FETCH_HEAD \
            || { echo "$GITHUB_SHA is not on main — a release is cut from main or not at all"; exit 1; }
          want="${GITHUB_REF_NAME#v}"
          for p in contracts wallet-transport wallet-core connector wallet-kit paymaster-sdk; do
            got=$(jq -r .version "packages/$p/package.json")
            [ "$got" = "$want" ] || { echo "packages/$p is $got, tag says $want"; exit 1; }
          done
```

**The commit is on `main`.** Not redundant with the gate — it is the other half of the claim, and
the only thing here that makes *released from `main`* true. It needs `fetch-depth: 0`, because
`merge-base` on a shallow clone has no history to walk.

**The tag names what it publishes.** This is what makes the tag→version mapping assertable rather
than conventional: `v3.0.0` publishes `3.0.0` or it publishes nothing.

Neither called workflow misbehaves on the tag path. The `github` context inside a called workflow is
the caller's, so `event_name` is `push` and both concurrency groups keep `cancel-in-progress: false`,
under keys (`ci-refs/tags/v3.0.0`, `determinism-refs/tags/v3.0.0`) distinct from the `main` ones and
from `release-`. D3's changeset assertion is `if: github.event_name == 'pull_request'` and skips.
`determinism.yml`'s `paths:` filter lives under `pull_request:` and is ignored by `workflow_call`, so
both determinism jobs run — correct for a gate.

#### The snapshot job's own guard

A release pull request's merge is a merge to `main` like any other, and by then every changeset has
been consumed. Publishing a snapshot from it would compute the *stable* version — there is no
pending bump left to add a prerelease suffix to — and put `3.0.0` on the registry under the `main`
dist-tag, ahead of its own tag:

```yaml
      - name: Publish a snapshot of this commit
        run: |
          pnpm changeset status --output=/tmp/status.json
          if [ "$(jq '[.releases[] | select(.type != "none")] | length' /tmp/status.json)" -eq 0 ]; then
            echo "no pending changesets — this commit releases nothing"
            exit 0
          fi
          pnpm changeset version --snapshot main
          pnpm changeset publish --tag main --no-git-tag
```

`--no-git-tag` because a snapshot is not a release: tagging git for every commit on `main` would put
six tags per merge in the repository, and `contents: read` on that job could not push them anyway.

#### What this gates for `giano-contracts`

The package ships `.sol` sources, `generated.ts` and `addresses.ts`, and nothing in the publish path
compiles Solidity: `prepublishOnly` is `pnpm build:ts`, which is tsup. Every Solidity guarantee comes
from a CI job, so every one of them has to be in the gate:

| Failure | Job that catches it | Workflow |
| --- | --- | --- |
| Solidity compile error | `generated.ts drift check (solc)` (`pnpm hh:compile`) and `Foundry tests` | `ci.yml` |
| Foundry test failure (28 `.t.sol` files, no Hardhat suite) | `Foundry tests` (`forge test -vvv`) | `ci.yml` |
| ABI drift against the committed `generated.ts` | `generated.ts drift check (solc)` | `ci.yml` |
| `addresses.ts` drift | `Build & typecheck packages (no solc)` | `ci.yml` |
| CREATE2 address change | `CREATE2 address determinism` | `determinism.yml` |
| Unsafe paymaster storage layout | `Paymaster storage layout is upgrade-safe` (`pnpm storage:check`) | `determinism.yml` |

No job in either workflow sets `continue-on-error`, so any of these fails its workflow, and a failed
workflow fails `needs`.

`e2e.yml` is deliberately not in the gate. It exercises the deployed stack rather than the published
artifacts, and at 8.5 minutes with live containers it is the wrong shape for a step that blocks an
irreversible publish.

The context half of the `cancel-in-progress` guard is documented: "When a reusable workflow is
triggered by a caller workflow, the `github` context is always associated with the caller workflow."
So `github.event_name` inside the called `ci.yml` is the caller's event, and one expression covers
both cases.

Whether a called workflow's **workflow-level** `concurrency` applies is not documented; GitHub speaks
only to the job-level key, warning against sharing a group between caller and callee, which `ci-*`,
`determinism-*` and `release-*` do not. Write the guard anyway — free if the nested block is ignored,
and if it is honoured it stops a second merge cancelling the first merge's gate and failing the
snapshot job between the third and fourth of six publishes. Confirm which from the first real run.

The trade is the standalone `CI` entry against each commit on `main`; those jobs now appear nested
under the `Release` run. Nothing is checked less, and one run tells the whole story of a merge.

> The alternative is `workflow_run`: keep `ci.yml` triggering on `main` and have `release.yml` fire
> on its completion. It also avoids the duplicate, and it is worse here — not because of the extra
> line it needs, but because there is no correct value for that line.
>
> `release.yml` has a single `actions/checkout`, and under `workflow_run` that one step has to pick a
> ref, because the event's default is not the commit that triggered it:
>
> - `ref: ${{ github.event.workflow_run.head_sha }}` — the commit CI actually validated. If `main`
>   has moved since (and under `concurrency` it often will have, because the release queues), the
>   publish ships a stale tree under a snapshot version naming an older commit.
> - the default — which for `workflow_run` is the **default branch head**, not the triggering commit.
>   That is the tip, which is what a release wants, but CI may never have run against it. The gate
>   then certifies one commit while the publish ships another.
>
> Nesting has no such choice to make. The called jobs and the publish job run against the same SHA,
> so "the commit that was tested" and "the commit being published" are one object by construction
> rather than by a correctly remembered `ref:`.

### 5.5 D5 — `main` requires green checks

`main` is protected, and the protection requires nothing:

```console
$ gh api repos/appliedblockchain/giano/branches/main --jq '{protected, protection}'
{"protected":true,
 "protection":{"enabled":true,
               "required_status_checks":{"checks":[],"contexts":[],"enforcement_level":"off"}}}
```

A classic rule, enabled, with an empty required-checks list and enforcement off.
`gh api repos/appliedblockchain/giano/rulesets` and `.../rules/branches/main` both return `[]`, so no
ruleset supplies it either. There is a rule, and it asks for no checks — which is why a pull request
showing nothing but a CodeRabbit check is mergeable. **Every merge to `main` now publishes, so the
pull request that can merge with no green check is a pull request that can publish unchecked.**

The release pull request is the sharp case: its merge is followed by a tag, and the tag publishes six
immutable versions. That particular hole is closed in the workflow rather than here — the tag path
runs the gate itself ([§5.4](#54-d4--the-release-cannot-publish-what-ci-has-not-checked)), so a
commit that cannot pass is unreleasable no matter what `main` accepted. What required checks add is
timing, not coverage: D4's gate runs *after* the merge, so a red gate means a commit already on
`main` that cannot be released, rather than a pull request that cannot be merged. D5 moves that
failure back before the merge, where a human is still looking at it.

**D5.** Add `ci.yml`'s four jobs as required status checks on `main`, by their display names — these
are what a pull-request run reports, and a pull-request run is what a required check evaluates:

- `Build & typecheck packages (no solc)`
- `wallet-api tests + OpenAPI drift`
- `generated.ts drift check (solc)`
- `Foundry tests`

`determinism.yml`'s two jobs are **not** on that list, and must not be. Its `pull_request` trigger is
path-filtered to `packages/contracts/**`, so on a release pull request — which touches only
`package.json`, `CHANGELOG.md` and `.changeset/*` — they would never report and the pull request
would sit at *Expected* forever. They gate the release through `needs`
([§5.4](#54-d4--the-release-cannot-publish-what-ci-has-not-checked)), which is the right mechanism
for a check that legitimately does not run on every pull request.

A repository setting, not a file, so the acceptance evidence is the readback above showing a
non-empty `contexts` and `enforcement_level` no longer `off`.

> The rest of the rule could not be read: this account has `admin: false` on the repository, and
> `GET /branches/main/protection` answers `404` to a non-admin rather than `403`. Required reviews,
> force-push and linear-history settings are therefore unverified here — someone with admin should
> confirm them while adding the checks.

### 5.6 Provenance of the published version

Two versions, one source.

A **snapshot** version is computed by `changeset version --snapshot main` from the pending changesets
plus `$GITHUB_SHA`: the base is what those changesets resolve to (`useCalculatedVersion`), the suffix
is the commit. Nothing is inferred from a branch name or a run number, and re-running the workflow on
the same commit recomputes the same string.

A **stable** version is whatever `changeset version` wrote into `package.json` in the release pull
request, from the same changesets — and the tag job refuses to publish unless the tag says the same
number. "Correct version" is therefore a property of the changesets in both cases, and D3 is what
makes the changesets exist.

---

## 6. R3 — a published version is never overridden

R3 has four attack surfaces. Three are already closed; one needs an explicit policy.

### 6.1 A workflow re-run at the same commit — closed

Changesets pre-checks each package with `npm info <name> --registry=<publishConfig.registry> --json`
and skips the ones already at that version. If the pre-check is stale, `pnpm publish` fails with
`E403 "cannot publish over the previously published version"`, and Changesets 2.31.1 classifies that
specific error as **`skipped`, not `failed`** (`isAlreadyPublishedError()`), so a re-run of a
published commit is green and publishes nothing.

This covers snapshots as well as stable releases, and only because of `{commit}` (D-a1). The
version a re-run computes is a pure function of the commit and the pending changesets, both of which
are fixed by the SHA, so the re-run tries to publish the exact same `3.0.0-main-<sha>` and is skipped.
`{datetime}` would compute a new version on every re-run and publish it — green, idempotent-looking,
and quietly adding a version per click.

Version 2.31.1 also handles the GitHub-Packages-specific wrinkle that makes this work at all:
GitHub Packages does not auto-assign the `latest` dist-tag the way npmjs does, so a bare
`npm info <name>` can return empty for a package that exists. 2.31.1 retries with
`npm info <name>@<version>` before concluding `E404`. Do not downgrade `@changesets/cli` below
2.31.1. The repository runs no Renovate or Dependabot, so the pin only moves when someone moves it.

### 6.2 A rebuilt artifact at the same version — closed by the registry

GitHub Packages rejects a second publish of an existing `name@version` regardless of tarball
contents. There is no `--force` in the publish path and none may be added.

### 6.3 Concurrent releases — closed

`release.yml` declares its concurrency in the string form, which means `cancel-in-progress: false`.
Keep that. **Do not** add `cancel-in-progress: true` to this workflow — a cancellation between the
third and fourth package publish leaves a partially released fixed group, which is the one state
R3's immutability makes unrecoverable except by burning another version.

`cancel-in-progress: false` does not buy a queue, though. GitHub: "At most one job or workflow run
can be `pending` in the concurrency group. When a new job or workflow run is queued, any existing
`pending` job or workflow run in the same group is canceled and replaced." So a group holds one run
in flight and one waiting, and a third arrival evicts the waiting one.

Keyed on the ref alone, every merge to `main` shares a group, and a burst of three merges silently
drops the middle one. That is not the harmless loss it first looks like. A `push`-triggered run is
pinned to the SHA of *its own* push event, not to whatever the tip is when it starts, so the dropped
run was the only thing that would ever have published `3.0.0-main-<that sha>`. Re-running it later
is possible; noticing that it needs re-running is not, because a cancelled-as-superseded run reads
like ordinary concurrency housekeeping. R2 says every merge publishes, and this is a path where one
quietly does not.

The SHA therefore goes in the key:

```yaml
concurrency: release-${{ github.ref }}-${{ github.sha }}
```

Two different merges are now never in the same group, so neither waits and neither is evicted. Runs
that do still share a group are runs at the same ref *and* the same SHA — re-runs — where the string
form's `cancel-in-progress: false` still protects a publish in flight, and where evicting a third
pending re-run costs nothing: it would recompute a version that is already on the registry and
Changesets would skip it ([§6.1](#61-a-workflow-re-run-at-the-same-commit--closed)).

The `main` and tag refs remain separate groups, so a tag publish is never queued behind or dropped
by merge traffic.

What this trades away is ordering. Two merges landing close together now publish concurrently
instead of one after the other, and the `main` dist-tag is the one piece of mutable state they
share: if the earlier run finishes last, `@main` points at the older of the two snapshots until the
next merge moves it. No version is overwritten — the versions are distinct and immutable, so R3 is
untouched — and `main` is a moving pointer by definition. Buying the ordering back means a mutex or
FIFO action wrapped around a job that holds `packages: write`, which is a worse trade than a
dist-tag that is briefly one merge stale.

### 6.4 Deletion and re-publication — needs a policy

GitHub Packages permits a user with admin on the package to **delete a version**, after which the
same version can be published again with different bytes. No registry setting prevents this; there
is no ECR-style `IMMUTABLE` flag for GitHub Packages npm.

**D6.** R3 is therefore enforced as: registry rejection (§6.1–6.2) **plus** a stated policy that
package-version deletion is never used, with package admin held by the same small set that holds
repository admin. Record it in the repository:

- `README.md` **Releasing** section: the snapshot-per-merge / tag-per-release flow, the constraint
  that a changeset may not name both a published and an ignored package, the `pnpm changeset --empty`
  escape, and the policy itself — a published `@appliedblockchain/giano-*` version is permanent, and
  a broken release is superseded by a new version, never replaced by deleting and re-publishing.
- Package settings: `Manage Actions access` for each of the six set to this repository only, and
  admin restricted to the org owners.

The container half of R3 is already enforced structurally: ECR repositories are `IMMUTABLE` and
`docker.yml`'s *Skip the ECR tag if this commit is already published* step probes
`aws ecr describe-images` before pushing, so a re-run is green and idempotent rather than red on
`ImageAlreadyExistsException`.

---

## 7. R4 / R5 — containers, ECR and GHCR

Built and verified. This section is the evidence, plus two discrepancies.

### 7.1 Verified

| Property | Where |
| --- | --- |
| The image list lives in exactly one place, `docker.yml`'s `setup` job, and is fanned out to both the build matrix and the merge matrix | `docker.yml` |
| All eight Dockerfiles exist at the R4 paths | checked on disk |
| All eight are built on **both** `linux/amd64` and `linux/arm64`, on native runners, on every event including PRs | `build` job matrix |
| All eight are pushed to GHCR by digest, then joined into one manifest list per image, tagged `type=ref,event=tag`, `latest` on the default branch, and `type=sha` (**R5**) | `build` + `merge` jobs |
| Six are copied into ECR **by digest** from the GHCR manifest list, so the bytes in ECR are the bytes validated and published to GHCR, not a rebuild (**R4**) | `merge` job, *Copy the manifest list to ECR* |
| The ECR tag is the full 40-character `$GITHUB_SHA`, which is what `infra/versions.json` and `terraform apply -var image_tag=…` consume verbatim | `merge` job |
| The ECR push is gated on `github.ref == 'refs/heads/main'`, matching what `giano-dev-gha-deploy` trusts (`repo:appliedblockchain/giano:ref:refs/heads/main`) | `merge` job + `infra/iac/github_oidc.vars.tf` |
| `giano-devnet` and `giano-contracts-deployer` carry `"ecr": ""` and reach GHCR only | `setup` job |
| AWS access is OIDC — no long-lived keys | `id-token: write` + `aws-actions/configure-aws-credentials@v5` |

### 7.2 Discrepancy 1 — the retention comment is wrong, and the floor may be real

`docker.yml` justifies `provenance: false` by stating the ECR lifecycle policy keeps
"30 in dev". `infra/iac/ecr.vars.tf` sets:

```hcl
variable "ecr_lifecycle_image_count" {
  default = { dev = 10, stg = 10, prd = 10 }
}
```

Ten, not thirty. The reasoning in the comment survives — an attestation manifest would still spend
retention budget — but the number is a third of what it claims, and the budget is a **floor for the
pinned `var.image_tag`**, not a cost knob: ten merges to `main` after a deploy, the image
`infra/versions.json` still points at can expire, and a task replacement or scale-out then fails to
pull. At the time of writing `infra/versions.json` pins `dev` to `6552edc`, three commits behind `main`.

**D7.** Correct the comment in `docker.yml` to state ten, and to say what ten means: a retention
floor under the pinned tag, not a cost setting. That file is H2's.

`infra/iac/` is not. Raising `ecr_lifecycle_image_count.dev` is a devops change and is recorded here
as **O-6** for whoever owns that module, with the reasoning above: the count has to clear the merge
rate between deploys, and 30 is the figure the workflow comment has been assuming.

### 7.3 Discrepancy 2 — nothing prunes GHCR

All eight images push to GHCR on every merge with a `sha-` tag, plus `latest`. There is no retention
policy and no cleanup job, so the `sha-` tags accumulate without bound. This is not an R4/R5
violation — R5 asks that the push be retained, and it is — but it is the kind of thing that becomes
an incident later. Recorded as **O-5**, not proposed as H2 work.

---

## 8. Consumption

R1 is only satisfied if the published packages are installable. Three things stand in the way.

### 8.1 The scope collision

`@appliedblockchain/giano-contracts` versions `1.0.0`–`2.0.1` are **public on npmjs.org**, with
`latest = 2.0.1`. They predate `publishConfig` (git tags `contracts-v1.0.1` … `contracts-v2.0.1`).
The other five names are free on npmjs.

The consequence for a consumer: `pnpm add @appliedblockchain/giano-contracts` in a project that has
not routed the scope resolves to **npmjs 2.0.1**, silently — an old, differently shaped package,
with none of the `addresses.ts` / `generated.ts` surface the current one exports. The five other
packages fail loudly with `E404`; contracts fails quietly with the wrong code.

Consumers must route the whole scope, as `specs/DEVELOPER-GUIDE.md` §2.1 and the package READMEs
already document:

```ini
# .npmrc in the consuming repo
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

with the standing caveat that routing the whole scope means no `@appliedblockchain/*` package can be
pulled from npmjs in that project.

**D8.** Deprecate the npmjs copies so the quiet failure becomes a loud one:

```fish
npm deprecate '@appliedblockchain/giano-contracts@<=2.0.1' \
  'Moved to GitHub Packages: https://npm.pkg.github.com (@appliedblockchain scope). See https://github.com/appliedblockchain/giano' \
  --registry=https://registry.npmjs.org
```

Deprecation prints on install and cannot break an existing consumer. Unpublishing is **not**
proposed — it would break anyone pinned to 2.0.1 and is itself a violation of the spirit of R3.

> This needs npmjs publish rights on the `@appliedblockchain` org, which CI does not have and should
> not get. It is a one-off human action, recorded here as an H2 acceptance item.

### 8.2 A public package that still needs a token

The six packages are public ([§4.1](#visibility--the-six-packages-will-be-public)), and they still
cannot be installed without a GitHub token: `npm.pkg.github.com` has no anonymous read path, for
public and private packages alike.

That inverts the usual reason for choosing GitHub Packages. Its one real advantage is private
distribution at no extra cost, and Giano is not using it, because the repository is public:

| | npmjs.org, public | GitHub Packages, public |
| --- | --- | --- |
| Token to install | none | **required, always** |
| Scope routing in the consumer's `.npmrc` | none | required, and all-or-nothing for `@appliedblockchain/*` |
| Anonymous CI in a client project | works | needs a secret provisioned per client |
| `npm audit`, provenance | supported | not supported |
| Version immutability | enforced | deletable by a package admin ([§6.4](#64-deletion-and-re-publication--needs-a-policy)) |

Giano's packages are an SDK for third-party dApp teams. Every one of those teams and their CI jobs
needs a PAT with `read:packages` to install a package that is already public — and the three places
this repo shows the consumer `.npmrc` (`DEVELOPER-GUIDE.md` §2.1, `packages/contracts/README.md`,
`packages/connector/README.md`) write `${GITHUB_TOKEN}` without saying which token, what scope, or
how an integrator outside the org gets one.

**This is a product decision, not a CI one, so this spec implements R1 as written** — GitHub
Packages, all six. It is recorded as **O-4** because R1 is the requirement that would have to change,
and the alternative is cheap: publishing the client-facing packages to npmjs.org costs nothing
(public scoped packages are free), removes the token and the scope-routing caveat for every
integrator, and resolves [§8.1](#81-the-scope-collision) by superseding the stale `giano-contracts`
rather than deprecating it.

### 8.3 The first published versions

Consumers reading R1's table will expect `0.1.0` for five of the six. What actually reaches GitHub
Packages first is a **snapshot**, `3.0.0-main-<sha>` for all six, and the first stable version is
`3.0.0`. Both follow from the fixed group (D1) and `useCalculatedVersion`, and the jump is intended —
it is what `.changeset/phase-4-version-alignment.md` decided.

Two things follow for a consumer:

- Tracking `main` means `pnpm add @appliedblockchain/giano-wallet-kit@main`, which resolves through
  the `main` dist-tag. `latest` stays empty until the first `v*` tag, so a plain
  `pnpm add @appliedblockchain/giano-wallet-kit` fails until then — correct, and worth saying once in
  the integration docs rather than debugging per integrator.
- A dependency written `^3.0.0-main-<sha>` also admits `3.0.0`, so a project pinned to a snapshot
  moves onto the stable release at its next resolution instead of stranding on a prerelease line.

The H2 page's version column and the `COMPATIBILITY.md` that `phase-4-version-alignment.md` refers to
(**which does not exist in the repository**) still need reconciling. See **O-3**.

---

## 9. Acceptance

Run in order. Each step is the evidence for the requirement named.

### 9.1 Pre-merge, on the branch carrying D1–D4

```fish
# R1 — the publishable set is exactly the six, and the fixed group matches it
pnpm ls -r --depth -1 --json | jq -r '.[] | select(.private != true) | .name' | sort
jq -r '.fixed[0][]' .changeset/config.json | sort

# R2 — the pending plan puts all six at one version, and wallet-kit is no longer 1.0.0
pnpm changeset status --output=/tmp/status.json
jq -r '.releases[] | select(.type != "none") | "\(.name)\t\(.oldVersion) -> \(.newVersion)"' /tmp/status.json

# R2 — the snapshot version is what we expect, and siblings pin exactly. On a throwaway tree:
pnpm changeset version --snapshot main
jq -r '.version, (.dependencies // {} | to_entries[] | select(.key|startswith("@appliedblockchain")) | "  \(.key) = \(.value)")' packages/wallet-kit/package.json
git checkout -- .   # discard; the snapshot bump is never committed

# R1 — release.yml's build list, verbatim: a fresh clone with no submodules and no Foundry
#      builds all six, in dependency order
pnpm --filter @appliedblockchain/giano-contracts build:ts
pnpm --filter @appliedblockchain/giano-wallet-transport build
pnpm --filter @appliedblockchain/giano-wallet-core build
pnpm --filter @appliedblockchain/giano-connector build
pnpm --filter @appliedblockchain/giano-wallet-kit build
pnpm --filter @appliedblockchain/giano-paymaster-sdk build
```

Expected: six names in the first two lists, identical; six releases all at `3.0.0`;
`3.0.0-main-<40-char sha>` with siblings pinned exactly, no caret; the build green with no submodules
checked out.

### 9.2 Post-merge — R2, R3

```fish
# The snapshot is on the registry under the `main` dist-tag
npm view '@appliedblockchain/giano-wallet-kit' dist-tags --registry=https://npm.pkg.github.com

# The tarball pins its siblings exactly, at the same snapshot version
npm pack '@appliedblockchain/giano-wallet-kit@main' --registry=https://npm.pkg.github.com
tar -xzOf appliedblockchain-giano-wallet-kit-*.tgz package/package.json \
  | jq '.dependencies | with_entries(select(.key | startswith("@appliedblockchain")))'

# R3 — re-run the same commit's Release; green, publishing nothing
gh run rerun <release-run-id>
gh run view <release-run-id> --log | grep -i 'skipped\|already published'
```

Expected: `main` pointing at `3.0.0-main-<sha>`; every `@appliedblockchain` dependency in the tarball
at that same version; the re-run green with each package reported as skipped, and no new version on
the registry.

Once enough merges have landed to have overlapped, R2's *every* merge is checkable directly — no
release-bearing commit on `main` may be missing its snapshot:

```fish
# Every published snapshot version, and every main SHA that carried a changeset
npm view '@appliedblockchain/giano-wallet-kit' versions --registry=https://npm.pkg.github.com
gh run list --workflow=release.yml --branch=main --json headSha,conclusion
```

Expected: no run with conclusion `cancelled`, and a `3.0.0-main-<sha>` for each SHA whose merge
carried a changeset.

### 9.3 The release pull request

- Its diff touches only `package.json`, `CHANGELOG.md` and `.changeset/*` — never a source file.
- The four required checks report green before it is mergeable.
- D3's changeset gate does **not** fire on it: the step prints *no publishable source touched*.

### 9.4 Post-tag — R1

```fish
# Six packages resolve on GitHub Packages at the tagged version
for p in giano-contracts giano-wallet-transport giano-wallet-core \
         giano-connector giano-wallet-kit giano-paymaster-sdk
    printf '%s ' $p
    npm view "@appliedblockchain/$p" version --registry=https://npm.pkg.github.com
end

# The five private packages resolve nowhere
for p in giano-wallet-api giano-wallet-web giano-paymaster-admin giano-example giano-e2e
    printf '%s ' $p
    npm view "@appliedblockchain/$p" version --registry=https://npm.pkg.github.com 2>&1 | grep -q E404
      and echo 'not published — correct'
      or echo 'PUBLISHED — R1 VIOLATION'
end

# Git tags and GitHub Releases exist, one per package
git fetch --tags && git tag --list '@appliedblockchain/*'
```

A tag on a commit that is not on `main`, or whose `package.json` versions disagree with the tag name,
must fail the *This tag is on main* step before anything is published.

### 9.5 R4 / R5

```fish
set sha (git rev-parse HEAD)

# Eight images on GHCR at this commit
for i in giano-wallet-api giano-wallet-web giano-paymaster-admin giano-example \
         giano-wallet-byo giano-bundler giano-devnet giano-contracts-deployer
    printf '%s ' $i
    docker buildx imagetools inspect "ghcr.io/appliedblockchain/$i:sha-"(string sub -l 7 $sha) \
      --format '{{json .Manifest}}' | jq -r '.digest // "MISSING"'
end

# Six on ECR, at the FULL sha, with the SAME digest as GHCR
aws ecr batch-get-image --repository-name giano-dev/wallet-api \
  --image-ids imageTag=$sha --query 'images[0].imageId.imageDigest' --output text
```

Expected: eight GHCR digests; the ECR digest for each of the six identical to its GHCR digest — the
copy-by-digest guarantee.

---

## 10. Risks and open items

| # | Item | Needs |
| --- | --- | --- |
| **O-3** | `.changeset/phase-4-version-alignment.md` refers readers to `COMPATIBILITY.md`, which does not exist anywhere in the repository. Four other places link to it as well. The first stable release is the moment it is needed — it is what explains why `giano-wallet-core` goes from `0.1.0` to `3.0.0`. Write it, or amend the changeset before the release pull request merges. |
| **O-4** | **Is GitHub Packages the right registry at all?** Answered: **yes, R1 as written.** The repository is public, so the six packages are public, and every integrator still needs a `read:packages` PAT and an all-or-nothing scope route to install one — [§8.2](#82-a-public-package-that-still-needs-a-token) has the comparison. Not revisited here; changing it is a change to R1. |
| **O-5** | No GHCR retention. Eight images × one `sha-` tag per merge, forever. Not an H2 requirement; worth a follow-up ticket with an `actions/delete-package-versions` scheduled job that keeps `latest`, every `v*` tag, and the last N `sha-` tags. |
| **O-6** | `ecr_lifecycle_image_count.dev` is 10, against a workflow comment that assumed 30 ([§7.2](#72-discrepancy-1--the-retention-comment-is-wrong-and-the-floor-may-be-real)). Ten merges to `main` after a deploy, the image `infra/versions.json` still pins can expire, and a task replacement or scale-out fails to pull. `infra/versions.json` pinned `dev` three commits behind `main` when this was written. **For devops** — `infra/iac/` is outside H2, and this spec changes nothing there. |
| **O-7** | Snapshot versions accumulate on GitHub Packages at one per changeset-carrying merge per package. Nothing prunes them, and unlike GHCR tags they are versions of a published package, so deletion is the policy-forbidden operation of [§6.4](#64-deletion-and-re-publication--needs-a-policy). The tension is real and unresolved: if the count becomes a problem, the answer is a retention policy written *before* any deletion, naming which prerelease versions may go and why that does not violate R3. |
| **R-1** | `@changesets/cli` is pinned `^2.31.1`. The GitHub-Packages `latest`-tag handling that makes the idempotent re-run work ([§6.1](#61-a-workflow-re-run-at-the-same-commit--closed)) arrived in that line, and `snapshot.prereleaseTemplate` needs 2.27 or later. A major bump must be re-verified against [§9.2](#92-post-merge--r2-r3) before merging. |
| **R-2** | `changeset version --snapshot` runs in the workflow and rewrites `package.json` on the runner. Those writes are never committed and the checkout is discarded, but a future step added *after* the snapshot publish would see mutated manifests. Keep the publish last in that job. |

---

## 11. Traceability

| Req | Satisfied by | Status |
| --- | --- | --- |
| **R1** — six packages published to `npm.pkg.github.com` under `@appliedblockchain` | [§4.1](#41-registry-scope-and-auth) routing + auth; [§4.2](#42-the-set-is-enumerated-and-the-enumeration-is-enforced) **D2** enumeration assertion | Built; first publish is the first merge after this lands |
| **R1** — the five private packages stay unpublished | `private: true` on all five ([§3](#3-current-state-verified)); asserted by **D2** and by the acceptance check in [§9.4](#94-post-tag--r1) | ✅ + assertion added |
| **R1** — installable, not merely published | [§4.3](#43-what-each-package-ships) `workspace:*` exact pins (**D-a2**); [§8.1](#81-the-scope-collision) **D8** | Pins done; D8 is a one-off outside CI |
| **R2** — every merge to `main` publishes, no manual publish step | [§5.1](#51-what-every-merge-to-main-means) snapshot per merge (**D-a**); **D4** CI gates the publish; per-SHA concurrency so no merge's run is evicted ([§6.3](#63-concurrent-releases--closed)) | ✅ for a merge that releases something; a merge with no pending changesets (an empty changeset, or a release pull request) publishes nothing, by design |
| **R2** — *at the correct version* | [§5.2](#52-d1--one-fixed-group-identical-to-the-publishable-set) **D1** fixed group = publishable set, plus the snapshot config; [§5.3](#53-d3--a-merge-that-should-publish-but-carries-no-changeset-fails) **D3** changeset gate; [§5.4](#54-d4--the-release-cannot-publish-what-ci-has-not-checked) the tag runs the gate and asserts its own version | ✅ |
| **R3** — no override by re-run | [§6.1](#61-a-workflow-re-run-at-the-same-commit--closed) Changesets skip-if-published, plus `{commit}` making a re-run recompute the same version | ✅ |
| **R3** — no override by rebuilt artifact | [§6.2](#62-a-rebuilt-artifact-at-the-same-version--closed-by-the-registry) registry rejection; [§6.3](#63-concurrent-releases--closed) no cancel-in-progress, and concurrent merges publish distinct versions | ✅ |
| **R3** — no override at all | [§6.4](#64-deletion-and-re-publication--needs-a-policy) **D6** deletion policy + package admin restriction | Policy written; settings are a follow-up |
| **R3** — containers | ECR `IMMUTABLE` + the `describe-images` skip in `docker.yml` | ✅ |
| **R4** — six images to ECR, by the stated repositories | [§7.1](#71-verified) — `docker.yml` `merge` job, copy-by-digest, full-SHA tag, `main`-only | ✅ built and verified |
| **R5** — all eight images retained on GHCR | [§7.1](#71-verified) — `build` + `merge` jobs, both arches, manifest list per image | ✅ built and verified |
| — | [§7.2](#72-discrepancy-1--the-retention-comment-is-wrong-and-the-floor-may-be-real) **D7** retention comment | Fixed in H2; the lifecycle count itself is **O-6**, for devops |
| — | [§8.1](#81-the-scope-collision) **D8** deprecate the npmjs copies of `giano-contracts` | One-off, needs npmjs org rights |

### Deliverables

| # | Change | File |
| --- | --- | --- |
| **D1** | `giano-wallet-kit` joins the `fixed` group; the four remaining private packages join `ignore`; the `snapshot` block sets `useCalculatedVersion` and `{tag}-{commit}` | `.changeset/config.json` |
| **D1a** | Inter-package dependencies become `workspace:*` (decision **D-a2**), so a snapshot tarball pins its siblings exactly | `packages/{connector,paymaster-sdk,wallet-core,wallet-kit}/package.json` |
| **D2** | Assert the publishable set is exactly the six R1 packages | `.github/workflows/ci.yml` |
| **D3** | A pull request touching publishable source must carry a changeset, with `package.json` and `CHANGELOG.md` excluded so a release pull request stays mergeable | `.github/workflows/ci.yml` |
| **D4** | `ci.yml` and `determinism.yml` drop `push: main`, gain `workflow_call`, `permissions: contents: read` and a PR-only `cancel-in-progress`; `release.yml` is rewritten into a `main` snapshot job behind `needs: [ci, determinism]`, keyed per SHA so no merge's run is evicted, and a tag release job behind the same `needs: [ci, determinism]` plus an ancestry and version assertion | `.github/workflows/{ci,determinism,release}.yml` |
| **D5** | `main`'s branch protection requires `ci.yml`'s four jobs as status checks | repository settings |
| **D6** | The release flow, the no-mixed-changeset constraint and the no-deletion policy are written down; package admin restricted | `README.md`, package settings |
| **D7** | ECR retention comment corrected to ten, and to what ten means | `.github/workflows/docker.yml` |
| **D8** | Deprecate `@appliedblockchain/giano-contracts@<=2.0.1` on npmjs | one-off, npmjs |
