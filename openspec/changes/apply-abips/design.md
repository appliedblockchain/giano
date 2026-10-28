## Context

The audit table is in proposal.md, under Why. These facts shape the approach:

- **Two pnpm workspaces.** The root workspace (`packages/*`, `services/*` except the example, `e2e`) and
  `services/custom-example` each have their own `pnpm-workspace.yaml` and lockfile. The example installs the
  *published* connector from GitHub Packages, the way an integrator would. Both workspace files carry the same
  security-floor `overrides` and supply-chain settings by hand ("keep them in step").
- **pnpm 11.15.1**, pinned via `packageManager` with a hash. It is above ABIP-6's 10.16 floor, and above 10.19 for
  version-specific `minimumReleaseAgeExclude`. Every CI and Dockerfile install already uses `--frozen-lockfile`.
- **88 range specifiers across 14 manifests.** 7 are `peerDependencies` of published libraries, which ABIP-7 exempts,
  so 81 must be pinned. The override values in both workspaces are carets.
- **Delivery.** `docker.yml` builds an image for every SHA on `main` and pushes it to GHCR, then to the `giano-dev` ECR
  namespace. `deploy.yml` rolls an environment when its key in `infra/versions.json` changes on `main`. The OIDC trust
  per environment is `var.gha_allowed_refs`, set to `main` for stg and prd. stg and prd are empty and not provisioned.
- **Keys.** The 1Password note `secrets-<env>` in vault `Giano <suffix>` is mirrored into Secrets Manager by
  `infra/iac/asm.tf`. It holds `sponsorship-signer-key` and `alto-executor-key`. `CANONICAL_DEPLOYER` is the placeholder
  `0x…dEaD`, and the deploy CLI refuses non-local chains while it is set. The Helm `deployer` job takes
  `DEPLOYER_PRIVATE_KEY` from the client's `secrets.existingSecret`. wallet-api already refuses
  `SPONSORSHIP_SIGNER_KIND=local` in production.
- **Permissions.** The implementer has push access but no admin access to the repository (`permissions.admin=false`),
  so rulesets and settings changes need DevOps. Org rulesets can't be read with the current token. `rules/branches/*`
  returns `[]` for both `main` and `production`.
- **Open PR #160** (`feat/guided-testnet-deployment`) rewrites the deploy tooling into `deploy/contracts/` and removes
  `deploy/sepolia`. It overlaps with ABIP-8's key-handling docs and touches `deploy/cli.ts`.

## Goals / Non-Goals

**Goals:**
- Each ABIP is one PR. Each PR is small enough to review alone and is mergeable without the PRs above it.
- Every requirement is enforced by a CI check where a machine can check it: ABIP-6 floor and exclusions, ABIP-7
  pins, ABIP-2 exceptions. Process-only requirements get a recorded procedure.
- `docs/abip-compliance.md` is the single record that an auditor reads for all six.
- Zero runtime behaviour change, and zero contract-address change.

**Non-Goals:**
- Running a key ceremony, rotating keys, provisioning stg/prd, or pushing images into stg/prd ECR namespaces.
- Adopting pnpm `catalog:`. ABIP-7 recommends it but does not require it. See D7.
- Pinning GitHub Actions to SHAs, or bumping any dependency version. Pinning keeps what is resolved today.

## Decisions

### D1 — One OpenSpec change, six stacked PRs, ordered so dependencies come first and DevOps blockers sit at the top
The stack is managed with GitHub's `gh stack` extension (`gh extension install github/gh-stack`). Each PR targets the
branch below it, and the bottom PR targets `main`:

| # | Branch | ABIP | Depends on | Merge blocked by |
|---|--------|------|-----------|------------------|
| 1 | `chore/abip-5-agents-md` | 5 | — | the user's team/Notion facts |
| 2 | `chore/abip-6-release-age` | 6 | 1 (AGENTS.md documents the lockfile rule) | — |
| 3 | `chore/abip-7-exact-pins` | 7 | 2 (pins must satisfy the 7-day window) | — |
| 4 | `chore/abip-2-close-gaps` | 2 | 3 (deployer image installs the pinned tree) | — |
| 5 | `chore/abip-8-key-ceremony` | 8 | 4 (verify-only mode runs in the hardened deployer) | — |
| 6 | `chore/abip-1-production-branch` | 1 | 5 (AGENTS.md lifecycle, compliance record) | DevOps: ruleset + `terraform apply` |

Why this order: 6 must come before 7, because pinning picks versions that already satisfy the new 7-day window.
ABIP-5 goes first because every later PR edits `AGENTS.md`'s pull-request section or the compliance record. ABIP-1
goes last because only it needs admin and infrastructure action. A blocked bottom PR would stall the whole stack.

Alternatives: six independent PRs off `main`. Rejected, because 6/7 and 2/8 really do conflict
(`pnpm-workspace.yaml`, `Dockerfile.deployer`, `docs/abip-compliance.md`). Numeric order (1, 2, 5, 6, 7, 8) was also
rejected, because it puts the DevOps-blocked PR at the bottom.

The stack is merged bottom-up with **merge commits**, as the earlier #130–#135 stack was. Squashing rewrites the base
of each PR above it. The OpenSpec change folder is committed in PR 1, and each PR ticks its own task group. The
`archive` step (sync specs, move the folder) runs in PR 6, or in a follow-up if PR 6 is still waiting on DevOps when the
rest merges.

### D2 — ABIP-5: `AGENTS.md` takes everything; `CLAUDE.md` is a one-line import plus nothing
The current `CLAUDE.md` rule ("no Co-Authored-By trailer") moves into `AGENTS.md` → Pull requests → Commits, so that
all agents see it, not only Claude. `CLAUDE.md` becomes `@AGENTS.md`.

Known values:
- GitHub `appliedblockchain/giano`, with read and open-PR permission, no force-push, no branch deletion.
- Slack #giano-dev (`C0BMMDG6H41`, private, PR announcements). Its permission is recorded as **read-only plus posting
  PR announcements only when the user asks**, which is a narrower exception spelled out per channel.
- No Jira, so the section is omitted.
- Branches: `feat/`, `fix/`, `chore/`, `docs/`, `deploy/` (versions.json bumps).
- Commits: Conventional Commits, scope optional, e.g. `feat(paymaster-admin): …`.
- Pre-commit: `pnpm lint`. Pre-merge: `gh pr checks <n>`, all required checks green.
- Merge: merge commit, which also keeps stacks intact. The squash-merged `chore: … (#159)` commits came from the
  changesets bot and from single-commit PRs. The user confirms the preferred default at apply time.

The user is asked at apply time for the team table, client contacts, the Notion teamspace and its ID and URL, the
Decision Log URL and the PM dashboard. #giano-mgt and #giano-portafino-integration are included only if the user wants
them in scope.

### D3 — ABIP-6: 10080 minutes, no third-party blanket exclusions, a small dependency-free checker
- `minimumReleaseAge: 10080` goes in both workspace files. The comment states ABIP-6 and the 7-day tier.
- Two blanket exclusions go: `postcss` and `baseline-browser-mapping`, in both workspaces. `@appliedblockchain/*` in
  the example stays (see "Our own releases" below). `postcss` and `baseline-browser-mapping` were added for a too-new security floor and a
  browserslist data package. Both resolve to versions older than 7 days today, which is verified at apply time. If
  either is still too young, it gets a version-specific entry with a removal date.
- `scripts/check-release-age.mjs` plus `.test.mjs`, in the same style as `check-dockerfiles.mjs`: no dependencies,
  `node --test`. It runs in `ci.yml` next to the Dockerfile check, and does three things:
  1. It parses `minimumReleaseAge` and `minimumReleaseAgeExclude` from both workspace files. The YAML is flat, so a
     line parser is enough, and no `yaml` dependency is needed.
  2. It rejects a value below 10080, and any exclusion that is not `name@exact`.
  3. It greps `.github/workflows/*.yml` and every `Dockerfile*` for a `pnpm install` without `--frozen-lockfile`.

  The stale-exclusion check needs the registry (`npm view <name>@<v> time`), so it runs only when exclusions exist, and
  only with network access. It is a separate `--registry` mode called from CI. Unit tests stub it.
- **Our own releases: a recorded deviation (amended 2026-10-28).** ABIP-6 says "no packages, including
  `@appliedblockchain/*`, are exempt". The first version of this change followed that, and every layer's
  `giano-example` build and e2e install then failed on the 4.0.0 release published the same day. The user decided that
  internal packages do not need the window: release.yml publishes them from reviewed commits on `main`, so the
  quarantine guards against nothing, and the lag only delays the example, its image and the e2e suite. So
  `services/custom-example` keeps `'@appliedblockchain/*'` in `minimumReleaseAgeExclude`, and the checker allows exactly
  that entry. `docs/abip-compliance.md` records the deviation; it needs the tech lead's sign-off and is to be raised
  as an amendment to ABIP-6. The root workspace needs no entry, because it links its packages with `workspace:`.
- **The existing lockfile.** pnpm checks the age only when it resolves, so the current lockfile can hold versions
  younger than 7 days. A known case is giano-connector 4.0.0 in the example, published 2026-10-27. Before PR 2
  merges, a one-off audit lists every lockfile entry younger than 7 days. Each one is either downgraded to the previous
  version or waited out by timing the merge. The result is recorded in the PR description.
- The `dependency-security` spec's earlier "exclude by name" escape hatch is replaced by ABIP-6's version-specific
  rule. See the delta spec.

Alternative: 4320 minutes (3 days, the MUST floor). Rejected by the user, because Giano is a wallet and the 7-day
SHOULD applies.

### D4 — ABIP-7: pin to the version the lockfile already resolves, so no package's resolution changes
ABIP-7's sample prompt says to pin to "the highest published version satisfying the range". That would be a hidden bulk
upgrade. ABIP-7's own upgrade-workflow rule forbids mixing upgrades into an unrelated PR. So each range is rewritten to
**the exact version that importer already resolves in its lockfile**, read from `pnpm-lock.yaml` `importers.<path>`.
The lockfile diff is then limited to specifier strings. A one-off script does the rewrite: it reads the lockfile and
rewrites the manifests. That script is not committed, but its output is checked by the committed range checker.

A plain `pnpm install` after changing override values re-resolves the whole tree and dedupes, which drops older
duplicates. So the lockfile's `specifier:` and `overrides:` lines are rewritten in place, by the same one-off script.
`pnpm install --frozen-lockfile`, followed by a plain `pnpm install` that must leave the file byte-identical, proves
the result is consistent.

- **Peer dependencies.** Published libraries keep their ranges (`viem ^2.31.0`, `react >=18`, `wagmi ^2.15.0`,
  `@rainbow-me/rainbowkit ^2.2.0`). The set of published libraries is the non-private `packages/*` manifests that have
  `publishConfig`. The checker computes it from that rule, not from a hard-coded list.
- **Overrides.** Each value is pinned to the version that override currently resolves to in the lockfile, for example
  `"^8.21.0"` → `"8.21.0"` (or whatever is locked). The selector keys keep their ranges, because they describe which
  resolutions are replaced. The same is done in the example's workspace file.
- **Published-library `dependencies` change** (contracts `zod`, tx-describe `@noble/hashes`, wallet-core `ox`/`uuid`,
  wallet-transport `ulid`). This narrows what integrators install, so it gets a **patch changeset** for those packages,
  explaining ABIP-7. Integrators can still dedupe through their own overrides.
- `scripts/check-pinned-versions.mjs` plus `.test.mjs` scans every tracked `package.json` outside `node_modules`,
  vendor and submodules, and both `overrides` maps. It runs in `ci.yml`.
- The changesets' `fixed` group and `workspace:*` internal references are untouched.

Alternative: pin to the highest version satisfying each range, as the ABIP's prompt suggests. Rejected, because it is a
bulk upgrade with real regression risk, and it would conflict with the 7-day gate on freshly published patches.

### D5 — ABIP-2 gaps: harden the deployer now that its blocker is gone; open the devnet issue
The deployer was ruled out of scope during H3 because `hardhat-foundry` shelled out to `forge`. #132 removed Hardhat
compilation: the image now runs `tsx deploy/cli.ts` against committed release bytecode. It also **receives the canonical
deployer key**, which makes it the most sensitive image Giano ships. It is not a fit for a community base running as
root with a shell.

The new layout:
- build on `dhi.io/node:22-alpine3.22-dev@sha256:…`, and run on the matching runtime digest that wallet-api already
  uses;
- the `/repo` tree is copied with `--chown` to the DHI user (1000), and `/out` is created owned by that user in the
  build stage;
- `deployer-entrypoint.sh` is ported to `deployer-entrypoint.mjs`, which calls the CLI functions in-process or spawns
  `node` with an argument array, never through a shell;
- `tsx` remains a runtime dependency of the image. It is an exact-pinned devDependency of contracts, and is allowed
  because it is the runtime loader, not a compiler toolchain. The alternative, bundling `deploy/cli.ts` to plain JS
  with tsdown at build time, is better. It is chosen if the CLI bundles cleanly, decided at apply time, and it removes
  `tsx` from the runtime.

  **Decided at apply time: bundle.** `tsdown.deployer.config.mts` bundles `deploy/cli.ts`, viem and zod into
  `dist-deployer/cli.mjs`. That directory sits one level below the package root, so every
  `import.meta.dirname`-relative path (`releases/`, `vendor/createx/`) still resolves. The final stage holds only that
  file, the releases, the CreateX data and the entrypoint.

The whole-file `*` exemption line is removed from the `abip-2-exceptions` block. `docs/abip-compliance.md` drops the
"out of scope" paragraph.

The `giano-devnet` tracking issue is opened ("Revisit giano-devnet base when a hardened Foundry/anvil image exists"),
and its link replaces "_to be opened_". `check-dockerfiles.mjs` gains a test that rejects a `*` whole-file entry.

The CREATE3 addresses cannot move: the image deploys release bytecode, and the address math uses neither the image
nor the compiler. As a check, the e2e compose `deploy` profile and a fresh-anvil deploy compare against
`pnpm deploy:cli addresses`.

### D6 — ABIP-8: repository work is the inventory, the runbook and the removal of key-handling paths
ABIP-8 is mostly a DevOps process. The repository's share is to make sure the process has a home, and that nothing in
the repository contradicts it.

- **`docs/key-ceremony.md` (new).** It holds the inventory table (spec), a per-key runbook entry and a link to ABIP-8.
  Each runbook entry gives the 1Password item and field (`secrets-prd` → `sponsorship-signer-key` /
  `alto-executor-key`), or for KMS/HSM keys their resource names. It also covers the address-publication step, and
  for the canonical deployer it links the README's "Switching to the real deployer" procedure. It does not repeat
  ABIP-8's commands.
- **Verify-only deploy mode.** `deploy/cli.ts core` stops requiring `DEPLOYER_PRIVATE_KEY` when every canonical
  contract is already present with the expected code. It checks first, signs only when something is missing, and
  exits with a clear "chain not adopted, adoption is a DevOps operation (docs/key-ceremony.md)" error when there is no
  key. The deployer image and Helm job inherit this behaviour: `DEPLOYER_PRIVATE_KEY` becomes optional, and the Helm
  README tells clients never to set it for a live chain.

  This is the one code change in PR 5. It has unit tests for the three paths: all present with no key, missing with
  no key, missing with a key.
- **Docs that hand a person the key are rewritten.** These are `specs/INFRASTRUCTURE.md` §13.1, the contracts README
  "Deploying" section, and `deploy/contracts/README.md` if #160 has merged. Commands with `DEPLOYER_PRIVATE_KEY=…` are
  marked local/testnet-only. Mainnet adoption points to the ceremony and DevOps.
- **The prd vault.** The `Giano prd` 1Password vault must not be readable by developers. Repository text can't enforce
  that, so it becomes a DevOps request task, together with "run the canonical-deployer ceremony". That task unblocks
  #160's public deployment.
- **Testnet keys.** The `dev` environment's Base Sepolia and Ethereum Sepolia keys are out of scope under ABIP-8's
  exceptions. The inventory says so explicitly, so that the exception is visible rather than implied.

Alternative: make the deployer image sign through KMS (the `hsm` path) in this PR. Rejected as scope creep. #160
already lists direct KMS/HSM signing as a known gap, and ABIP-8 is satisfied by ceremony custody alone.

### D7 — No pnpm catalog in this change
ABIP-7 RECOMMENDS `catalog:` for monorepos. Moving 14 manifests to a catalog at the same time as pinning would mix two
mechanical rewrites and make review harder. `services/custom-example` also can't share the root catalog, because it is
a separate workspace. Catalog adoption is recorded as a follow-up in `docs/abip-compliance.md` under ABIP-7.

### D8 — ABIP-1: prd follows `production`; dev/stg stay on `main`; promotion is main → production
- `deploy.yml` changes:
  - it adds `production` to `push.branches`;
  - the plan step computes which environments may deploy from the branch it runs on (`main` → `dev`, `stg`;
    `production` → `prd`) and ignores changes to other keys, with a notice;
  - for prd it runs `git merge-base --is-ancestor <tag> HEAD` before emitting rows;
  - a `workflow_dispatch` for `prd` fails unless `github.ref == refs/heads/production`.
- `infra/iac/github_oidc.vars.tf` sets `prd = ["production"]`. A `terraform apply` in the prd workspace is a DevOps
  task. The workspace does not exist yet, so this is a recorded default that takes effect when prd is provisioned.
- **Branch creation.** `git push origin main:production`, at the PR 6 merge commit, needs only push rights, so the
  implementer can do it. The **ruleset** needs an admin, so it goes as a DevOps request with these settings:
  - target `production`;
  - require a pull request with 1 approval, dismissing stale approvals;
  - require the CI status checks;
  - block force pushes and deletion;
  - no bypass actors.

  `main` keeps its current state. ABIP-1 explicitly avoids burdening the default branch.
- **Images.** `docker.yml` keeps building on `main` only. Every commit promoted to `production` is already a `main`
  commit with a published image. Pushing images into the prd ECR namespace is part of the future prd provisioning, and
  is out of scope.
- **Promotion flow** (spec): bump `.prd` on `main`, which deploys nothing; open a PR `main` → `production`; get an
  approval; merge with a merge commit; the deploy runs. This is documented in `AGENTS.md`, in
  `specs/INFRASTRUCTURE.md` §15.1 and in the deploy workflow's header comment.

Alternative: stg also deploys from `production`. Rejected by the user, because only prd is production under ABIP-1.

## Risks / Trade-offs

- [The 7-day window blocks a critical fix in a transitive dependency] → ABIP-6 allows exclusions only for direct
  dependencies. For a transitive fix, the override mechanism (security floors) is used once the fixed version is 7
  days old. Until then, the advisory goes into the dependency-security accepted residuals with its date.
- [Exempting `@appliedblockchain/*` departs from ABIP-6] → It is bounded to that one scope in the example workspace,
  enforced by the checker, recorded in `docs/abip-compliance.md`, and to be signed off by the tech lead. Integrators
  under ABIP-6 still face the 7-day lag on our releases; the example no longer shows that lag.
- [The existing lockfile has entries younger than 7 days when PR 2 lands] → The one-off lockfile age audit runs before
  merge, and the merge is timed so that no entry is too young. Merge after 2026-11-03 for the 4.0.0 release.
- [Pinning published-library `dependencies` causes duplicate installs for integrators] → A patch changeset explains it.
  The affected dependencies are small, `zod`, `ox`, `uuid`, `ulid` and `@noble/hashes`, and integrators can dedupe
  through overrides.
- [A stack PR is edited after review and the PRs above it go stale] → `gh stack` rebases the stack. Every PR's CI runs
  on its own head. The stack is merged bottom-up and is not squashed.
- [#160 merges before or after PR 5] → PR 5 rebases onto whichever lands. If #160 lands first, PR 5 edits
  `deploy/contracts/README.md`. If #160 lands later, its author gets the ABIP-8 rule in review: no mainnet
  `DEPLOYER_PRIVATE_KEY` instructions.
- [The DevOps-blocked PR 6 holds up the archive] → PRs 1–5 merge independently, and the archive moves to a follow-up.
- [The deployer on DHI breaks the Helm pre-install job: `/out` permissions, no shell] → The e2e compose `deploy`
  profile and a fresh-anvil run must pass in PR 4. Writability of `/out` gets the same check as the SPA images'
  writable paths.
- [Hidden org-level rulesets already target `production`] → The DevOps request asks them to confirm and reuse an org
  ruleset if one exists. That satisfies ABIP-1's "naming convention for automatic application" intent.

## Migration Plan

1. Merge PRs 1–5 bottom-up as they are approved. Each one is self-contained and needs no deploy.
2. PR 6: merge it, create `production` from `main`, file the DevOps request for the ruleset and the prd
   `terraform apply`. Until prd exists, the prd path is dormant.
3. File the DevOps request for the canonical deployer ceremony and the prd vault access policy. When the ceremony
   produces the address, a normal PR replaces the placeholder, following the README switch procedure.
4. Rollback: every PR is reverted on its own, top-down if needed. Reverting PR 6 restores main-only deploys. Reverting
   PR 2 or PR 3 restores the old window or the old ranges, with the lockfile reverted in the same commit.

## Open Questions

- The merge-strategy default recorded in `AGENTS.md` (D2) is merge commit, to be confirmed by the user when PR 1 is
  written.
- Bundle `deploy/cli.ts` with tsdown or keep `tsx` in the deployer runtime (D5). Decided by whether the CLI bundles
  cleanly. Both options satisfy the spec.
- Whether #giano-mgt belongs in `AGENTS.md`'s Slack table. The user is asked with the other ABIP-5 facts.
