# Giano — CI build, push and tag configuration

This document is the **how** for H2 (*CI build, push and tag configuration*, 3 SP), whose **what**
is the five requirements R1–R5 reproduced in [§2](#2-the-requirements). It specifies the release
pipeline: which packages are published, where, at what version, under what guarantee of
immutability, and how containers reach GHCR and ECR.

Everything asserted about the current state in [§3](#3-current-state-verified) was read out of this
repository, its workflow-run history, or the registries themselves on 2026-09-15; each claim carries
its evidence. [§11](#11-traceability) maps every requirement to the section that satisfies it.

Status: **draft for technical review.** [§10](#10-risks-and-open-items) lists six open items, two of
which — **O-1** (what R2's "no manual publish step" means) and **O-4** (whether GitHub Packages is
the right registry for a public repository) — need a call before implementation starts.

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

The npm half is **half built**. `.github/workflows/release.yml` exists, runs green on every merge to
`main`, and maintains a `chore: version packages` PR — but **nothing has ever been published to
`npm.pkg.github.com`**, because publishing only happens when that PR merges, and it has not. The
open PR is #94, dated 2026-09-11.

The work is what stands between "the workflow runs" and "R1–R3 hold": eight deliverables, D1–D8.

### 1.2 Decisions taken in this spec

| # | Decision | Why |
| --- | --- | --- |
| **D-a** | Keep the Changesets two-step flow (merge → version PR → merge → publish). Do **not** publish a version derived from the commit on every merge. | A published version is permanent (R3). Deriving it from a commit means every merge burns a version number for a change that may not be releasable, and the six packages are fixed-versioned, so one merge would burn one version across all six. The manual step Changesets leaves is *approving a version*, not *running a publish* — R2's "no manual publish step" is satisfied. See [§5.1](#51-what-every-merge-to-main-means). This is the call flagged as **O-1**. |
| **D-b** | The publishable set stays **explicitly enumerated**, and CI asserts the enumeration. Never derived from a directory glob. | Publishing must be an intentional act. Under R3 the two failure modes are not symmetrical: a package that should have shipped and did not is fixed in the next release, while one published by accident is permanent, at a version that can never be reused. A glob makes creating a directory sufficient to publish; a list plus an assertion makes it require a deliberate edit that a reviewer sees. [§4.2](#42-the-set-is-enumerated-and-the-enumeration-is-enforced). |
| **D-c** | Immutability is the **registry's** guarantee, asserted in CI — not a convention. | GitHub Packages rejects a re-publish over an existing version with `E403`; ECR repositories are `IMMUTABLE`. Both are already true. What is missing is the assertion that they stay true. [§6](#6-r3--a-published-version-is-never-overridden). |
| **D-d** | `main` is the only ref that publishes npm packages. Tags publish nothing to npm. | Changesets creates the git tags *after* publishing, from the version PR merge commit. A `v*` tag push is a container-only event (docker.yml), already the case for ECR. |
| **D-e** | Keep the approval gate on the version PR's CI. Do **not** swap `changesets/action` onto an App or PAT token to make those runs start automatically. | The PR is merged by a human anyway, so approving is one more click by the same person — while auto-running would re-run CI, E2E and Docker on every force-update of a branch nobody has decided to merge (30 such runs are queued on the current one). It also avoids owning an App private key with `contents: write` and `pull_requests: write` for no gain. Branch protection, not an auto-run, is what makes the PR safe. [§5.5](#55-d5--the-version-pr-cannot-merge-unchecked). |

### 1.3 Out of scope

Staging and production ECR namespaces (`giano-stg/*`, `giano-prd/*`), container signing/attestation,
and the rollout workflow (`deploy.yml`, which reads `infra/versions.json` and is specified in
[`specs/INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §15).

**`infra/iac/` is devops territory and this spec changes nothing in it.** Terraform is read here as
evidence — ECR repository names, tag immutability, lifecycle counts, the OIDC role's trusted refs —
and where a reading turns up something worth changing, it is raised as an open item addressed to
whoever owns that module, never as an H2 deliverable. **O-6** is the one such item.

Publishing Giano packages **to npmjs.org** is out of scope as implemented — R1 names
`npm.pkg.github.com` and this spec builds that. It is raised as **O-4** rather than settled here,
because the repository being public removes the reason the registry was chosen. The one npmjs action
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
| Anything has been published to `npm.pkg.github.com` | ❌ **No** | The only publish path is the `changesets/action` publish branch, which runs only when no changesets are pending; 11 changesets are pending and PR #94 is open |
| The version PR carries green required CI | ❌ **No** | `gh pr checks 94` reports only CodeRabbit; the `CI`, `E2E` and `Docker images` runs on `changeset-release/main` sit in `action_required` |
| `main` is protected | ✅ | `gh api .../branches/main` → `protected: true`, a classic rule (`rulesets` and `rules/branches/main` are both `[]`) |
| That protection requires any status check | ❌ **No** | same call → `required_status_checks: {checks: [], contexts: [], enforcement_level: "off"}`; [§5.5](#55-d5--the-version-pr-cannot-merge-unchecked) |
| `@appliedblockchain/giano-contracts` already exists on **npmjs.org** | ⚠️ **Yes**, `1.0.0`–`2.0.1`, `latest = 2.0.1`, public | `npm view … --registry=https://registry.npmjs.org`. Published before `publishConfig` was introduced — see git tags `contracts-v1.0.1`…`contracts-v2.0.1` |
| The other five exist on npmjs.org | ✅ No — all `E404` | same |
| `docker.yml` builds all eight images and pushes all eight to GHCR | ✅ | `.github/workflows/docker.yml`, `setup` job image list; all eight Dockerfiles exist at the stated paths |
| `docker.yml` copies the six ECR-backed images to ECR by digest, on `refs/heads/main` only | ✅ | `docker.yml` `merge` job; gated on `matrix.image.ecr != '' && github.ref == 'refs/heads/main'` |
| ECR repository names match R4 | ✅ | `infra/iac/ecr.vars.tf` `ecr_repos = ["wallet-api", "wallet-web", "paymaster-admin", "example", "wallet-byo", "bundler"]` |
| ECR repositories are `IMMUTABLE` in every environment | ✅ | `infra/iac/ecr.vars.tf` `ecr_image_tag_mutability` |

### 3.1 What the pending release would produce

`pnpm changeset status` resolves the 11 pending changesets to:

| Package | Old | New | Note |
| --- | --- | --- | --- |
| `giano-contracts` | 2.1.0 | **3.0.0** | fixed group |
| `giano-wallet-core` | 0.1.0 | **3.0.0** | fixed group — jumps from 0.1.0 |
| `giano-wallet-transport` | 0.1.0 | **3.0.0** | fixed group |
| `giano-connector` | 0.1.0 | **3.0.0** | fixed group |
| `giano-paymaster-sdk` | 0.1.0 | **3.0.0** | fixed group |
| `giano-wallet-kit` | 0.1.0 | **1.0.0** | ⚠️ **not in the fixed group** |
| `giano-wallet-api` | 0.1.0 | 0.2.0 | private — not published |
| `giano-wallet-web` | 0.1.0 | 1.0.0 | private — not published |
| `giano-paymaster-admin` | 0.1.0 | 0.1.1 | private — not published |
| `giano-example` | 0.1.0 | 0.1.0 | private, and `ignore`d |
| `giano-e2e` | 0.0.0 | 0.0.0 | private |

The 0.1.0 → 3.0.0 jump is intended: `.changeset/phase-4-version-alignment.md` states that fixed-mode
versioning ships all Giano packages at one version. `giano-wallet-kit` landing at 1.0.0 is **not**
intended — it is simply missing from `fixed` in `.changeset/config.json`. That is D1.

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
        # `changeset publish` publishes whatever is not `private: true`; release.yml's list only
        # controls what gets BUILT. This ties the two together, so a new workspace package is
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

Every workspace dependency is declared `workspace:^`. `pnpm publish` rewrites that to the concrete
range at pack time — `workspace:^` → `^3.0.0` — so the published tarballs carry resolvable ranges.
This is why `changeset publish` must run through pnpm, which it does: Changesets 2.31.1's
`getPublishTool()` detects pnpm and spawns `pnpm publish --no-git-checks`.

---

## 5. R2 — every merge publishes at the correct version

### 5.1 What "every merge to `main`" means

The flow has two merges, and only the second one publishes:

```
  PR with a changeset ──merge──▶ main
                                  │
                                  ├─ release.yml: changesets/action sees pending changesets
                                  │  └─ opens / force-updates PR "chore: version packages"
                                  │     (branch changeset-release/main): versions bumped,
                                  │     CHANGELOGs written, changesets consumed
                                  │
  "chore: version packages" ──merge──▶ main
                                  │
                                  └─ release.yml: no pending changesets
                                     └─ pnpm changeset publish
                                        ├─ npm publish ×6 to npm.pkg.github.com
                                        └─ git tags @appliedblockchain/giano-x@3.0.0, pushed
                                           + a GitHub Release per tag
```

R2's "no manual publish step" holds: no human runs `npm publish`, sets a version by hand, or
dispatches a workflow. The human act is reviewing and merging a version diff, which is the approval
of what version to burn — and burning a version is permanent under R3. Read strictly as "the merge
itself puts an artifact on the registry", the alternative is snapshot releases; see **O-1**.

### 5.2 D1 — `giano-wallet-kit` joins the fixed group

`.changeset/config.json`, `fixed`, gains the sixth name:

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
```

With this, the pending release resolves all six to `3.0.0` instead of five at `3.0.0` and wallet-kit
at `1.0.0`. The fixed group is then *identical* to the publishable set, which is the invariant worth
having: one Giano version, published six times.

The five private packages stay outside the group deliberately — their versions are cosmetic, since
images are tagged by commit SHA, never by package version (`infra/versions.json`,
[`specs/INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §15.1). `.changeset/config.json` `ignore` currently
names only `giano-example`; leaving the other four to be bumped is harmless but inconsistent — see
**O-2**.

### 5.3 D3 — a merge that should publish, but carries no changeset, fails

Nothing today stops a PR that changes `packages/wallet-core/src` from merging without a changeset.
It merges, no version PR appears for it, and the change ships inside whatever release happens next —
silently, at a version that does not describe it. That is the practical way R2 breaks.

Add to `ci.yml`, in the `packages` job:

```yaml
      - uses: actions/checkout@v7
        with:
          # changeset status --since needs the merge base; the default shallow clone has no main
          fetch-depth: 0
```

```yaml
      - name: A change to a publishable package carries a changeset
        # Only on PRs: on main the changeset has already been consumed by the version PR.
        if: github.event_name == 'pull_request'
        run: |
          if git diff --quiet origin/${{ github.base_ref }}...HEAD -- packages/; then
            echo "no publishable package touched — no changeset required"
            exit 0
          fi
          pnpm changeset status --since=origin/${{ github.base_ref }}
```

`changeset status --since` exits non-zero when changed packages have no changeset. The `git diff`
guard keeps infra-only and docs-only PRs green. An intentional no-release change (a comment, a test)
is unblocked the documented way — `pnpm changeset --empty`.

### 5.4 D4 — the release cannot publish what CI has not checked

`release.yml` and `ci.yml` both trigger on `push: branches: [main]` and run **concurrently**.
`release.yml` builds the six packages, so a compile break stops it — but no unit test, no OpenAPI
drift check and no `addresses.ts` drift check gates publication. A green publish over a red CI is
possible today.

Make `ci.yml` callable, and let the release be the *only* thing that runs it on `main`:

```yaml
# .github/workflows/ci.yml
name: CI

on:
  # No `push: branches: [main]`. On main, CI runs exactly once — as the gate inside
  # release.yml below. A second, standalone run on the same SHA would prove the same
  # thing twice and gate nothing.
  pull_request:
  workflow_call:

concurrency:
  group: ci-${{ github.ref }}
  # A PR supersedes its own older runs. A run on main must NOT: it is a release gate, and
  # cancelling it aborts `release` mid-publish — the one state §6.3 says is unrecoverable
  # under R3. Inside a called workflow the `github` context is the CALLER's, so this is
  # `push` on a merge to main and `pull_request` on a PR. Same shape docker.yml already uses.
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

`determinism.yml` takes the same treatment, for the same reason and with one difference: its
`pull_request` trigger is path-filtered to `packages/contracts/src/**`, `hardhat.config.ts` and
`foundry.toml`, and that filter stays. Only the unconditional `push: branches: [main]` is replaced by
`workflow_call`.

```yaml
# .github/workflows/release.yml
jobs:
  ci:
    name: CI
    uses: ./.github/workflows/ci.yml

  determinism:
    name: Determinism
    uses: ./.github/workflows/determinism.yml

  release:
    name: Changesets version / publish
    needs: [ci, determinism]
    runs-on: ubuntu-latest
    # … unchanged
```

One run of each per `main` SHA, and the publish cannot start until both are green. Neither needs
`secrets: inherit` — their jobs use only `actions/checkout`, pnpm, Node and Foundry.

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

The context half of that guard is documented: "When a reusable workflow is triggered by a caller
workflow, the `github` context is always associated with the caller workflow." So `github.event_name`
inside the called `ci.yml` is the caller's event, and one expression covers both cases.

Whether a called workflow's **workflow-level** `concurrency` applies is not documented; GitHub speaks
only to the job-level key, warning against sharing a group between caller and callee, which `ci-*`
and `release-*` do not. Write the guard anyway — free if the nested block is ignored, and if it is
honoured it stops a second merge cancelling the first merge's gate and failing `release` between the
third and fourth of six publishes. Confirm which from the first real run.

The trade is the standalone `CI` entry against each commit on `main`; those jobs now appear nested
under the `Release` run. Nothing is checked less, and one run tells the whole story of a merge. The
version PR is unaffected — it is a pull request, so it draws CI from the `pull_request` trigger on
approval ([§5.5](#55-d5--the-version-pr-cannot-merge-unchecked)).

> The alternative is `workflow_run`: keep `ci.yml` triggering on `main` and have `release.yml` fire
> on its completion. It also avoids the duplicate, and it is worse here — not because of the extra
> line it needs, but because there is no correct value for that line.
>
> `release.yml` has a single `actions/checkout`, and under `workflow_run` that one step has to pick a
> ref, because the event's default is not the commit that triggered it:
>
> - `ref: ${{ github.event.workflow_run.head_sha }}` — the commit CI actually validated. If `main`
>   has moved since (and under `concurrency` it often will have, because the release queues), then
>   `changeset version` consumes an older set of changesets, `changeset publish` ships a stale tree,
>   and `changesets/action` pushes `changeset-release/main` from a detached HEAD behind the tip.
> - the default — which for `workflow_run` is the **default branch head**, not the triggering commit.
>   That is the tip, which is what a release wants, but CI may never have run against it. The gate
>   then certifies one commit while the publish ships another.
>
> Nesting has no such choice to make. The called jobs and the release job run against the same SHA,
> so "the commit that was tested" and "the commit being published" are one object by construction
> rather than by a correctly remembered `ref:`.

### 5.5 D5 — the version PR cannot merge unchecked

Every `CI`, `E2E` and `Docker images` run on `changeset-release/main` lands in `action_required`.
This is **not** a repository setting that can be turned off. It is GitHub's recursion guard, and it
is unconditional:

> "When you use the repository's `GITHUB_TOKEN` to perform tasks, events triggered by the
> `GITHUB_TOKEN` will not create a new workflow run."

Pull requests are the one partial exception, and the exception is precisely this state: when a
workflow using `GITHUB_TOKEN` opens or updates a pull request, the resulting `pull_request` event
"creates workflow runs in an approval-required state". The runs exist as records and do not execute
until someone approves them. `release.yml` passes `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}` to
`changesets/action`, so this is every run the version PR produces.

**The approval gate is kept.** GitHub documents a remedy — "you can use a GitHub App installation
access token or a personal access token instead of `GITHUB_TOKEN`" — and this spec declines it:

- The version PR is merged by a human anyway ([§5.1](#51-what-every-merge-to-main-means)), so
  approving is one more click by the same person at the same moment.
- `changeset-release/main` is force-updated on **every** changeset-carrying merge, and
  `pull_request` fires on `synchronize`. Auto-running would re-run the full suite on each update to a
  branch nobody has decided to merge. The current PR has **30 queued runs** — ten each of `CI`, `E2E`
  and `Docker images`, at roughly 3 min, 8.5 min and sixteen jobs apiece.
- An App private key held as a repository secret with `contents: write` and `pull_requests: write` is
  a credential to own and rotate, bought here for nothing but eager evaluation.

CI on the version PR stays lazy: it runs when a human signals intent to release, by approving it.

What is missing is the requirement, not the run. `main` is protected, and the protection requires
nothing:

```console
$ gh api repos/appliedblockchain/giano/branches/main --jq '{protected, protection}'
{"protected":true,
 "protection":{"enabled":true,
               "required_status_checks":{"checks":[],"contexts":[],"enforcement_level":"off"}}}
```

A classic rule, enabled, with an empty required-checks list and enforcement off.
`gh api repos/appliedblockchain/giano/rulesets` and `.../rules/branches/main` both return `[]`, so no
ruleset supplies it either. There is a rule, and it asks for no checks — which is why a version PR
showing nothing but a CodeRabbit check is mergeable. **The one PR whose merge publishes six immutable
packages is the one PR that can merge with no green check.**

**D5.** Add `ci.yml`'s four jobs as required status checks on `main`, by their display names — these
are what a PR run reports, and a PR run is what a required check evaluates:

- `Build & typecheck packages (no solc)`
- `wallet-api tests + OpenAPI drift`
- `generated.ts drift check (solc)`
- `Foundry tests`

`determinism.yml`'s two jobs are **not** on that list, and must not be. Its `pull_request` trigger is
path-filtered to `packages/contracts/**`, and a version PR touches only `package.json`,
`CHANGELOG.md` and `.changeset/*` — so those checks would never report and the PR would sit at
*Expected* forever. They gate the release through `needs` ([§5.4](#54-d4--the-release-cannot-publish-what-ci-has-not-checked)),
which is the right mechanism for a check that legitimately does not run on every PR.

This is what makes keeping the approval gate safe. A required check that has never reported blocks
the merge as *Expected — waiting for status to be reported*, and an `action_required` run has never
reported. The version PR is blocked until a human approves the runs and they pass.

A repository setting, not a file, so the acceptance evidence is the readback above showing a
non-empty `contexts` and `enforcement_level` no longer `off`.

> The rest of the rule could not be read: this account has `admin: false` on the repository, and
> `GET /branches/main/protection` answers `404` to a non-admin rather than `403`. Required reviews,
> force-push and linear-history settings are therefore unverified here — someone with admin should
> confirm them while adding the checks.

> Revisit the token swap only if the approval click becomes the bottleneck in practice. It is a
> one-line change plus a credential, and nothing else in this spec depends on which way it goes.

### 5.6 Provenance of the published version

`changeset publish` publishes whatever version sits in `package.json` at that commit, and that
version was written by `changeset version` in the merged PR, from the changesets. "Correct version"
is therefore a property of the changesets, and D3 is what makes the changesets exist. There is no
version computed in CI, no version inferred from a tag, and no version derived from a commit — by
D-a, deliberately.

---

## 6. R3 — a published version is never overridden

R3 has four attack surfaces. Three are already closed; one needs an explicit policy.

### 6.1 A workflow re-run at the same commit — closed

Changesets pre-checks each package with `npm info <name> --registry=<publishConfig.registry> --json`
and skips the ones already at that version. If the pre-check is stale, `pnpm publish` fails with
`E403 "cannot publish over the previously published version"`, and Changesets 2.31.1 classifies that
specific error as **`skipped`, not `failed`** (`isAlreadyPublishedError()`), so a re-run of a
published commit is green and publishes nothing.

Version 2.31.1 also handles the GitHub-Packages-specific wrinkle that makes this work at all:
GitHub Packages does not auto-assign the `latest` dist-tag the way npmjs does, so a bare
`npm info <name>` can return empty for a package that exists. 2.31.1 retries with
`npm info <name>@<version>` before concluding `E404`. Do not downgrade `@changesets/cli` below
2.31.1. The repository runs no Renovate or Dependabot, so the pin only moves when someone moves it.

### 6.2 A rebuilt artifact at the same version — closed by the registry

GitHub Packages rejects a second publish of an existing `name@version` regardless of tarball
contents. There is no `--force` in the publish path and none may be added.

### 6.3 Concurrent releases — closed

`release.yml` declares `concurrency: release-${{ github.ref }}` in its string form, which means
`cancel-in-progress: false`. A second merge queues behind a publish in flight rather than cancelling
it mid-way through six sequential publishes.

Keep it. **Do not** add `cancel-in-progress: true` to this workflow — a cancellation between the
third and fourth package publish leaves a partially released fixed group, which is the one state
R3's immutability makes unrecoverable except by burning another version.

`cancel-in-progress: false` does not buy a queue, though. GitHub: "At most one job or workflow run
can be `pending` in the concurrency group. When a new job or workflow run is queued, any existing
`pending` job or workflow run in the same group is canceled and replaced." Under a burst of merges,
release runs are dropped.

Usually harmless: a release run acts on the tip and consumes every pending changeset, so the run that
replaced a dropped one does its work. One edge. If the dropped run was the one that would have
**published** — queued when the changeset queue was empty — and its replacement finds a fresh
changeset, the replacement opens a version PR and publishes nothing. The versions already in
`package.json` are never published or tagged, and the next `changeset version` bumps past them,
leaving a CHANGELOG entry for a version that is not on the registry. A number is skipped; nothing is
corrupted, and the recovery is the next release. `queue: max` would preserve dropped runs, but each
still executes against the tip it finds, so it changes how many run, not what any of them do.

### 6.4 Deletion and re-publication — needs a policy

GitHub Packages permits a user with admin on the package to **delete a version**, after which the
same version can be published again with different bytes. No registry setting prevents this; there
is no ECR-style `IMMUTABLE` flag for GitHub Packages npm.

**D6.** R3 is therefore enforced as: registry rejection (§6.1–6.2) **plus** a stated policy that
package-version deletion is never used, with package admin held by the same small set that holds
repository admin. Record it in the repository:

- `README.md` release section: a published `@appliedblockchain/giano-*` version is permanent; a
  broken release is superseded by a new version, never replaced.
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

### 8.3 The first published version is 3.0.0

Consumers reading R1's table will expect `0.1.0` for five of the six. With the fixed group (D1) the
first version ever to reach GitHub Packages is `3.0.0` for all six. That is intended — it is what
`.changeset/phase-4-version-alignment.md` decided — but the H2 page's version column and the
`COMPATIBILITY.md` that changeset refers to (**which does not exist in the repository**) must be
reconciled before the version PR merges. See **O-3**.

---

## 9. Acceptance

Run in order. Each step is the evidence for the requirement named.

### 9.1 Pre-merge, on the branch carrying D1–D4

```fish
# R1 — the publishable set is exactly the six, and the fixed group matches it
pnpm ls -r --depth -1 --json \
  | jq -r '.[] | select(.private != true) | .name' | grep giano | sort

jq -r '.fixed[0][]' .changeset/config.json | sort

# R2 — the pending plan puts all six at one version
pnpm changeset status --output=/tmp/status.json
jq -r '.releases[] | select(.newVersion) | "\(.name)\t\(.oldVersion) -> \(.newVersion)"' /tmp/status.json

# R1 — release.yml's build list, verbatim: a fresh clone with no submodules and no Foundry
#      builds all six, in dependency order
pnpm --filter @appliedblockchain/giano-contracts build:ts
pnpm --filter @appliedblockchain/giano-wallet-transport build
pnpm --filter @appliedblockchain/giano-wallet-core build
pnpm --filter @appliedblockchain/giano-connector build
pnpm --filter @appliedblockchain/giano-wallet-kit build
pnpm --filter @appliedblockchain/giano-paymaster-sdk build
```

Expected: six names in the first two lists, identical; all six at `3.0.0` in the third; the build
green with no submodules checked out.

### 9.2 The version PR

- Before approval, the PR is **not mergeable**: the four required checks read *Expected — waiting
  for status to be reported*, and GitHub blocks merge.
- After a reviewer approves the pending runs, `gh pr checks <n>` shows the four `CI` jobs as
  **completed/success**.
- Its diff touches only `package.json`, `CHANGELOG.md` and `.changeset/*` — never a source file.

### 9.3 Post-merge — R1, R2

```fish
# Six packages resolve on GitHub Packages at the same version
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

# The published tarball carries a resolvable range, not workspace:^
npm pack '@appliedblockchain/giano-wallet-kit' --registry=https://npm.pkg.github.com
tar -xzOf appliedblockchain-giano-wallet-kit-*.tgz package/package.json \
  | jq '.dependencies | with_entries(select(.key | startswith("@appliedblockchain")))'

# Git tags and GitHub Releases exist, one per package
git fetch --tags && git tag --list '@appliedblockchain/*'
```

### 9.4 Post-merge — R3

```fish
# Re-run the published Release workflow at the same commit; it must be green and publish nothing
gh run rerun <release-run-id>
gh run view <release-run-id> --log | grep -i 'skipped\|already published'
```

Expected: green, with each package reported as skipped. Nothing new on the registry, no new tag.

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
| **O-1** | **The reading of R2.** This spec keeps Changesets' two-step flow (D-a): a merge to `main` produces a version PR, and merging *that* publishes. If R2 must mean "the merge itself puts an artifact on the registry", the mechanism is `changeset version --snapshot <sha>` + `changeset publish --tag <branch>` on every merge, publishing e.g. `3.0.0-main-6552edc`. That satisfies the letter of R2 and is compatible with R3 (each SHA is a distinct version), at the cost of an unbounded stream of prerelease versions on GitHub Packages and a `latest` that only moves on a real release. **A call from the technical lead.** |
| **O-2** | The four private packages that are not in `ignore` (`giano-wallet-api`, `giano-wallet-web`, `giano-paymaster-admin`, `giano-e2e`) receive version bumps and CHANGELOGs they never publish. Harmless, but it means a reviewer of the version PR reads eleven version changes when six matter. Either add them to `ignore` or drop `giano-example` from it and accept the noise consistently. |
| **O-3** | `.changeset/phase-4-version-alignment.md` refers readers to `COMPATIBILITY.md`, which does not exist anywhere in the repository. The first release is the moment it is needed — it is what explains why `giano-wallet-core` goes from `0.1.0` to `3.0.0`. Write it, or amend the changeset before the version PR merges. |
| **O-4** | **Is GitHub Packages the right registry at all?** The repository is public, so the six packages will be public, so the registry's one genuine advantage — free private distribution — is not being used. Every integrator still needs a `read:packages` PAT and an all-or-nothing scope route to install a public package. R1 names the registry, so this spec implements it; changing it is a change to R1. [§8.2](#82-a-public-package-that-still-needs-a-token) has the comparison. **A call from the technical lead**, and the one worth making before the first publish rather than after, since D8 and the `COMPATIBILITY.md` wording both depend on the answer. |
| **O-5** | No GHCR retention. Eight images × one `sha-` tag per merge, forever. Not an H2 requirement; worth a follow-up ticket with a `actions/delete-package-versions` scheduled job that keeps `latest`, every `v*` tag, and the last N `sha-` tags. |
| **O-6** | `ecr_lifecycle_image_count.dev` is 10, against a workflow comment that assumes 30 ([§7.2](#72-discrepancy-1--the-retention-comment-is-wrong-and-the-floor-may-be-real)). Ten merges to `main` after a deploy, the image `infra/versions.json` still pins can expire, and a task replacement or scale-out fails to pull. `infra/versions.json` pinned `dev` three commits behind `main` when this was written. **For devops** — `infra/iac/` is outside H2, and this spec changes nothing there. |
| **R-1** | `@changesets/cli` is pinned `^2.31.1`. The GitHub-Packages `latest`-tag handling that makes the idempotent re-run work (§6.1) arrived in that line. A major bump must be re-verified against §9.4 before merging. |

---

## 11. Traceability

| Req | Satisfied by | Status |
| --- | --- | --- |
| **R1** — six packages published to `npm.pkg.github.com` under `@appliedblockchain` | [§4.1](#41-registry-scope-and-auth) routing + auth (already correct); [§4.2](#42-the-set-is-enumerated-and-the-enumeration-is-enforced) **D2** | Mechanism built, **never exercised** — blocked on the version PR merging |
| **R1** — the five private packages stay unpublished | `private: true` on all five ([§3](#3-current-state-verified)); asserted by **D2** and by the acceptance check in [§9.3](#93-post-merge--r1-r2) | ✅ + assertion to add |
| **R2** — every merge to `main` publishes, no manual publish step | [§5.1](#51-what-every-merge-to-main-means) flow; **D4** (CI gates the publish), **D5** (the version PR cannot merge unchecked) | Partly built; **O-1** open on the reading |
| **R2** — *at the correct version* | [§5.2](#52-d1--giano-wallet-kit-joins-the-fixed-group) **D1** fixed group = publishable set; [§5.3](#53-d3--a-merge-that-should-publish-but-carries-no-changeset-fails) **D3** changeset gate | **Broken today** — wallet-kit diverges to 1.0.0; no changeset enforcement |
| **R3** — no override by re-run | [§6.1](#61-a-workflow-re-run-at-the-same-commit--closed) Changesets skip-if-published, verified in 2.31.1 | ✅ |
| **R3** — no override by rebuilt artifact | [§6.2](#62-a-rebuilt-artifact-at-the-same-version--closed-by-the-registry) registry rejection; [§6.3](#63-concurrent-releases--closed) no cancel-in-progress | ✅ |
| **R3** — no override at all | [§6.4](#64-deletion-and-re-publication--needs-a-policy) **D6** deletion policy + package admin restriction | Policy to write |
| **R3** — containers | ECR `IMMUTABLE` + the `describe-images` skip in `docker.yml` | ✅ |
| **R4** — six images to ECR, by the stated repositories | [§7.1](#71-verified) — `docker.yml` `merge` job, copy-by-digest, full-SHA tag, `main`-only | ✅ built and verified |
| **R5** — all eight images retained on GHCR | [§7.1](#71-verified) — `build` + `merge` jobs, both arches, manifest list per image | ✅ built and verified |
| — | [§7.2](#72-discrepancy-1--the-retention-comment-is-wrong-and-the-floor-may-be-real) **D7** retention comment | Fix in H2; the lifecycle count itself is **O-6**, for devops |
| — | [§8.1](#81-the-scope-collision) **D8** deprecate the npmjs copies of `giano-contracts` | One-off, needs npmjs org rights |

### Deliverables

| # | Change | File |
| --- | --- | --- |
| **D1** | `giano-wallet-kit` joins the `fixed` group | `.changeset/config.json` |
| **D2** | Assert the publishable set is exactly the six R1 packages | `.github/workflows/ci.yml` |
| **D3** | A PR touching `packages/` must carry a changeset | `.github/workflows/ci.yml` |
| **D4** | `ci.yml` and `determinism.yml` drop `push: main`, gain `workflow_call`, and guard `cancel-in-progress` to PRs; the release job `needs: [ci, determinism]` | `.github/workflows/ci.yml`, `.github/workflows/determinism.yml`, `.github/workflows/release.yml` |
| **D5** | `main`'s branch protection requires `ci.yml`'s four jobs as status checks | repository settings |
| **D6** | No-deletion policy, package admin restricted | `README.md`, package settings |
| **D7** | ECR retention comment corrected to ten, and to what ten means | `.github/workflows/docker.yml` |
| **D8** | Deprecate `@appliedblockchain/giano-contracts@<=2.0.1` on npmjs | one-off, npmjs |
