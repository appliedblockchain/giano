> **gh-stack commands** (from `gh stack --help`, 2026-10-27):
> - `gh stack init <branch>` starts the stack on `main`.
> - `gh stack add <branch>` adds the next layer on top of the current branch.
> - `gh stack view` shows the stack.
> - `gh stack submit --auto` pushes all branches atomically and creates or updates the PRs. Without `--open`, the PRs
>   are created as drafts.
> - `gh stack rebase` does a cascading rebase. Use `--upstack` or `--downstack` to limit it, and `--no-trunk` to skip
>   `main`.
> - `gh stack sync` pulls the remote state.
> - `gh stack merge` merges bottom-up.
> - `gh stack up`, `gh stack down`, `gh stack top` and `gh stack bottom` move between layers.

## 0. Stack setup

- [x] 0.1 Install the stack tooling with `gh extension install github/gh-stack`. Read `gh stack --help` and record the
  actual create, push and rebase commands at the top of this file. The design assumes the extension exists but does
  not assume its CLI shape.
- [x] 0.2 Start the stack from an up-to-date `main`, with the six branches of design D1 in order. `gh stack init` creates
  the bottom branch, and `gh stack add` adds each later branch once the layer below it is committed:
  `chore/abip-5-agents-md` → `chore/abip-6-release-age` → `chore/abip-7-exact-pins` → `chore/abip-2-close-gaps` →
  `chore/abip-8-key-ceremony` → `chore/abip-1-production-branch`.
- [x] 0.3 Commit `openspec/changes/apply-abips/` on the bottom branch, PR 1. Each later PR ticks only its own group.

## 1. ABIP-5: AGENTS.md (PR 1, `chore/abip-5-agents-md`)

- [x] 1.1 Ask the user for the values design D2 lists as unknown:
  - the team table (name and role);
  - client contacts;
  - the Notion teamspace name, ID and URL;
  - the Decision Log URL and the PM dashboard URL;
  - whether #giano-mgt or #giano-portafino-integration are in scope;
  - confirmation that the default merge strategy is a merge commit.
- [x] 1.2 Write `AGENTS.md` from the ABIP-5 template:
  - the scope rule;
  - Team;
  - GitHub, with its permission note;
  - Notion;
  - Slack: #giano-dev `C0BMMDG6H41`, read-only, with posting PR announcements allowed only when the user asks;
  - Pull requests: lifecycle, `pnpm lint`, `gh pr checks`, merge strategy, branch, commit and PR-title naming, and the
    no-AI-attribution rule moved from `CLAUDE.md`.

  Omit Jira. The line about the 7-day lag for consuming our own releases is added by PR 2 (task 2.7), not as a
  placeholder here. Notion has no teamspace yet, so the in-scope resources are the `Giano` coordination page and its
  tickets database (read + write) and the ABIPs register (read only). There are no client contacts. GitHub permission
  has one recorded exception: `gh stack` may force-update the branches of a stack you own.
- [x] 1.3 Replace `CLAUDE.md` with `@AGENTS.md`. Verify that a fresh Claude Code session loads it and that the
  attribution rule still reaches the agent.
- [x] 1.4 Run a secret-shape scan over both files (32-byte hex, `ghp_`, `xox`, PEM): there must be no hits.
- [x] 1.5 Create `docs/abip-compliance.md`'s summary table rows for ABIP-1, 5, 6, 7 and 8 as "in progress (apply-abips)",
  and add the ABIP-5 section.
- [x] 1.6 Open PR 1 as a draft against `main`, with no AI attribution, per `AGENTS.md`.

## 2. ABIP-6: minimum release age (PR 2, `chore/abip-6-release-age`)

- [x] 2.1 Write `scripts/check-release-age.mjs` and `scripts/check-release-age.test.mjs`, dependency-free and run with
  `node --test`. The check:
  - parses both `pnpm-workspace.yaml` files;
  - fails on `minimumReleaseAge < 10080`;
  - fails on any exclusion that is not `name@x.y.z`;
  - fails on a `pnpm install` without `--frozen-lockfile` in `.github/workflows/*.yml` or `Dockerfile*`;
  - in `--registry` mode, fails on an exclusion older than the window.

  Write the tests first. They cover the exact `postcss`, `'@appliedblockchain/*'` and frozen-lockfile cases from the
  delta spec.
- [x] 2.2 Run the check on the current tree and confirm it fails with the expected findings: 1440 in both files, and
  the three blanket exclusions.
- [x] 2.3 Audit the lockfile age for both lockfiles: list every resolved `name@version` published less than 7 days ago,
  using a one-off script that is not committed. For each one, downgrade it to the newest version older than 7 days, or
  record that the merge waits until it ages. Known case: the example's `@appliedblockchain/giano-connector@4.0.0`,
  published 2026-10-27.

  **Result (2026-10-27):** of the 1069 versions in the root lockfile and the 629 in the example's, none on npm is
  younger than 7 days. The example's `@appliedblockchain/giano-connector@4.0.0` and `giano-wallet-transport@4.0.0`
  were published at 2026-10-27 08:06:34 UTC. Downgrading to 3.x would undo #159's move to CREATE3 addresses, so
  **PR 2 waits: it merges no earlier than 2026-11-03 08:07 UTC (published at 08:06:34 UTC, per CI).**
- [x] 2.4 Set `minimumReleaseAge: 10080` in both workspace files, with an ABIP-6 comment. Remove `postcss`,
  `baseline-browser-mapping` and `'@appliedblockchain/*'`. Where removing one breaks `pnpm install`, replace it with a
  version-specific entry, and give the advisory or reason and a removal date.
- [ ] 2.5 Run `pnpm install --frozen-lockfile` in both workspaces and confirm the lockfiles are unchanged. The root
  passes, unchanged, with the line "Lockfile passes supply-chain policies (1069 entries)". The example needs a
  `read:packages` token, which this machine lacks; it is verified by the `giano-example` image build in CI. If 2.3
  forced a change, commit it alone, as `chore(deps): …`, per the lockfile-discipline requirement.
- [x] 2.6 Wire `node --test scripts/check-release-age.test.mjs` and `node scripts/check-release-age.mjs` into `ci.yml`
  next to the Dockerfile check, and run `--registry` when exclusions exist.
- [x] 2.7 Update the docs:
  - `AGENTS.md`: the lockfile rule and the 7-day lag for our own releases;
  - the `services/custom-example` README: "a new Giano release can be installed 7 days after publication";
  - `docs/abip-compliance.md`: the ABIP-6 section, giving the window per workspace and the active exclusions, of which
    there should be none.
- [ ] 2.8 Gates: `pnpm build`, `pnpm lint` and the CI job set all pass. Open PR 2 on top of PR 1.

## 3. ABIP-7: exact pins (PR 3, `chore/abip-7-exact-pins`)

- [x] 3.1 Write `scripts/check-pinned-versions.mjs` and `scripts/check-pinned-versions.test.mjs`, dependency-free.
  - Scope: every tracked `package.json` outside `node_modules`, `vendor/` and `packages/contracts/lib/`, plus both
    `overrides` maps.
  - Accepted: exact versions, `workspace:` and `catalog:`. Git dependencies must use a 40-character SHA.
  - Peer ranges are allowed only in non-private packages under `packages/*` that have `publishConfig`.

  Write the tests first, covering every specifier form in the delta spec.
- [x] 3.2 Run the check on the current tree. Confirm 81 manifest violations, 7 accepted library peer ranges, and every
  caret override value.
- [x] 3.3 With a one-off script that is not committed, rewrite each violating specifier to the version its importer
  resolves in `pnpm-lock.yaml`, or in the example's lockfile. Rewrite each override value to its locked version. Do not
  upgrade anything.
- [ ] 3.4 Run `pnpm install` in both workspaces. Confirm that the lockfile diff touches only specifiers and no resolved
  versions. Then run `pnpm install --frozen-lockfile` and confirm it passes.

  **Finding:** a plain `pnpm install` re-resolves the whole tree when override values change. It dropped 6 older
  duplicates (`debug@4.4.1`, `fdir@6.4.4`, `hasown@2.0.2`, `picomatch@4.0.5`, `process-warning@5.0.0`,
  `semver@7.7.2`) and moved one dev-only peer context. To keep the change specifier-only, the original lockfile's
  `specifier:` and `overrides:` lines were rewritten instead: 104 lines in the root, 62 in the example.

  **Root:** `pnpm install --frozen-lockfile` passes, and a following plain `pnpm install` leaves it byte-identical;
  `packages` and `snapshots` are unchanged. **Example:** this needs a `read:packages` token (see 2.5), and is verified
  by the `giano-example` image build in CI.
- [x] 3.5 Add a patch changeset for contracts, tx-describe, wallet-core and wallet-transport, explaining that runtime
  `dependencies` are now exact under ABIP-7.
- [x] 3.6 Wire the check and its tests into `ci.yml`.
- [ ] 3.7 Gates (local, 2026-10-27): build passes, except the contracts' forge-based `gen:abis`, since Foundry is not
  installed locally. The package tests pass (402), wallet-api passes (387), and typecheck passes. forge, determinism,
  `release:verify` and e2e run in this PR's CI; `determinism.yml` triggers on `packages/contracts/package.json`.
  Required:
  - `pnpm build`, the package tests and the wallet-api tests;
  - `forge test`, the determinism workflow and `release:verify`, with canonical addresses unchanged;
  - the e2e suite, run once.
- [x] 3.8 Update the docs:
  - `AGENTS.md`: the upgrade workflow, meaning edit the pin, commit the lockfile in the same PR, and include no
    unrelated changes;
  - `docs/abip-compliance.md`: the ABIP-7 section, covering the peer exemption, the override rule and the `catalog:`
    follow-up (D7).

  Open PR 3.

## 4. ABIP-2: close the remaining gaps (PR 4, `chore/abip-2-close-gaps`)

- [x] 4.1 Open the GitHub issue "Revisit giano-devnet base when a hardened Foundry/anvil image exists" and link it in
  `docs/abip-compliance.md` in place of "_to be opened_".
- [x] 4.2 Decide between bundling `deploy/cli.ts` with tsdown and keeping `tsx` at runtime (design D5, open question).
  Record the choice in design D5. **Chosen: bundle.** It bundles cleanly into one 748 kB ESM file
  (`tsdown.deployer.config.mts`), so the runtime has no `node_modules`, no `tsx` and no TypeScript. Issue: #165.
- [x] 4.3 Port `packages/contracts/scripts/deployer-entrypoint.sh` to `deployer-entrypoint.mjs`:
  - same env contract (`RPC_URL`, `CHAIN_ID`, `ROLE_ADMIN`, `RELEASE`, `DEPLOY_TESTING`, `PAYMASTER_FUND_ETH`,
    `OUT_DIR`);
  - same registry JSON output;
  - no shell, and no `exec` or `spawn` with `shell: true`.

  It adds `DEPLOYER_IMPERSONATE=true`, for local chains only (the CLI refuses `--impersonate` elsewhere). Without it,
  the image could not run anywhere while `CANONICAL_DEPLOYER` is the placeholder: no key can match `0x…dEaD`.
- [x] 4.4 Rewrite `packages/contracts/Dockerfile.deployer`:
  - DHI Node `-dev` build stage and runtime final stage, pinned to the digests wallet-api uses;
  - files copied with `--chown` to the DHI user, and `/out` owned by that user;
  - no `RUN` in the final stage;
  - an exec-form `ENTRYPOINT ["node", "…/deployer-entrypoint.mjs"]`.
- [x] 4.5 Remove `packages/contracts/Dockerfile.deployer *` from the `abip-2-exceptions` block. Add a
  `check-dockerfiles` test that rejects a `*` whole-file entry. Confirm the policy check passes on the new Dockerfile.
- [x] 4.6 Gates:
  - `docker build` of the deployer;
  - `docker run --entrypoint sh` fails;
  - the main process UID is non-zero;
  - the e2e compose `deploy` profile against a fresh anvil writes `/out/<chainId>.json` and a registry entry whose
    addresses equal `pnpm deploy:cli addresses`.

  No compose file has a `deploy` profile, so the image was run directly:
  - against `giano-devnet` (baked state), it verifies all four contracts as already deployed and writes both files;
  - against a blank anvil, after `install-createx` / `install-entrypoint`, it deploys all four at the canonical
    addresses, then the two `giano.test.*` contracts with `DEPLOY_TESTING=true`;
  - with no key and no impersonation, it fails with a clear message;
  - `sh` exits 127, the UID is 1000, the image size is 154 MB, and there is no `node_modules`.
- [x] 4.7 Update `docs/abip-compliance.md`: drop the "out of scope" paragraph, move the deployer row to "DHI Node", and
  leave devnet as the only exception. Open PR 4.

## 5. ABIP-8: key ceremony (PR 5, `chore/abip-8-key-ceremony`)

- [x] 5.1 Write `docs/key-ceremony.md`.
  - The inventory table has a row for each key: canonical deployer, sponsorship signer, bundler executor, paymaster
    `ROLE_ADMIN` and its timelock proposers and executors, and platform-admin API keys (out of scope, not private
    keys). Dev and testnet keys are listed as out of scope.
  - Each row gives the key's scope, its store per environment class and the service that consumes it.
  - The runbook gives, for each in-scope key, the vault item and field or the KMS/HSM resource, and the address
    publication step. It links ABIP-8 and the README's canonical-deployer switch procedure.
- [x] 5.2 Add a verify-only path to `deploy/cli.ts core`:
  - when every canonical contract is present with the expected code, no `DEPLOYER_PRIVATE_KEY` is needed;
  - when a contract is missing and there is no key, it fails with the "adoption is a DevOps operation" message.

  Add unit tests for all three paths: all present with no key, missing with no key, missing with a key.
- [x] 5.3 Make `DEPLOYER_PRIVATE_KEY` optional in the deployer entrypoint from 4.3. In the Helm chart, document in the
  README and in `values.yaml` comments that clients must never put the canonical deployer key in
  `secrets.existingSecret` for a live chain.
- [x] 5.4 Rewrite the key-handling docs: `specs/INFRASTRUCTURE.md` §13.1, the "Deploying" section of
  `packages/contracts/README.md`, `deploy/contracts/README.md` (if #160 has merged), and the CLI usage text. Mark
  `DEPLOYER_PRIVATE_KEY=…` commands as local/testnet only, and point mainnet adoption to `docs/key-ceremony.md`.

  **Wider than planned:** `specs/INTEGRATION.md`, `specs/DEVELOPER-GUIDE.md` and `specs/CHAIN-ADOPTION.md` also handed
  integrators the key, so they were rewritten too, and the spec's document list was updated. Also, one key owns every
  chain's salts, so the canonical deployer is in scope on testnets as well. `deploy/sepolia/` is left to #160, which
  removes it, and `docs/key-ceremony.md` flags it as superseded.
- [x] 5.5 Confirm that wallet-api's existing refusal of `SPONSORSHIP_SIGNER_KIND=local` under
  `GIANO_DEPLOYMENT_CLASS=production` has a test. Add one if it is missing. It was missing: added to
  `test/sponsorship-signer.test.ts`, refused in production and accepted on testnet, both with sponsorship on (the
  check is gated on `SPONSORSHIP_ENABLED`).
- [ ] 5.6 Draft the DevOps request with the `ae-devops-request` skill and show it to the user before filing. It asks
  DevOps to:
  - run the ABIP-8 ceremony for the permanent canonical deployer;
  - confirm that the development team has no read access to the `Giano prd` 1Password vault;
  - generate the prd sponsorship-signer and executor keys by ceremony, when prd is provisioned.
- [x] 5.7 Update `docs/abip-compliance.md` with the ABIP-8 section: inventory link, the DevOps-owned ceremony, and the
  pending ceremony for the canonical deployer. Gates: the contracts tests, the e2e `deploy` profile with no key against
  an already-deployed devnet, and `pnpm lint`. Open PR 5.

  Results: `test:deploy` passes 4/4 (wired into `ci.yml`), the contracts typecheck passes, and the wallet-api signer
  tests pass 23/23. The image with no key, against `giano-devnet`, verifies all four contracts and writes `/out`
  (exit 0). Against a blank chain it fails with the DevOps message (exit 1). Biome is clean on the changed files.

## 6. ABIP-1: production branch (PR 6, `chore/abip-1-production-branch`)

- [ ] 6.1 `deploy.yml`:
  - add `production` to `push.branches`;
  - make the plan step branch-aware (`main` → dev/stg, `production` → prd), with a notice for keys that are ignored;
  - add the prd ancestor check (`git merge-base --is-ancestor`);
  - make a `workflow_dispatch` for prd refuse any ref other than `refs/heads/production`;
  - update the header comment.
- [ ] 6.2 Test the plan logic locally against fixture `before` and `after` files. Cover a prd bump on main (no rows), a
  prd bump on production (prd rows), a non-ancestor tag (fails), and a dispatch from main for prd (fails). If it
  cannot be run directly, extract the plan into a script that can be tested.
- [ ] 6.3 Set `gha_allowed_refs.prd = ["production"]` in `infra/iac/github_oidc.vars.tf`. `terraform fmt` and
  `validate` must pass (glibc container, per the repository's gotcha).
- [ ] 6.4 Document the promotion flow (bump on main, then a PR main → production, then a merge commit, then the deploy)
  in `specs/INFRASTRUCTURE.md` §15.1 and in `AGENTS.md`'s Pull requests lifecycle.
- [ ] 6.5 Update `docs/abip-compliance.md` with the ABIP-1 section: branch, ruleset settings, who can change them, and
  prd being the only environment on `production`.
- [ ] 6.6 Draft the DevOps request and show it to the user before filing. It covers:
  - the `production` ruleset: PR required, 1 approval, stale approvals dismissed, required CI checks, no force push
    or deletion, no bypass;
  - confirming whether an org ruleset already targets `production`;
  - the prd OIDC `terraform apply` when the prd workspace is provisioned.
- [ ] 6.7 Open PR 6. After it merges, with the user's go-ahead, create the branch with `git push origin main:production`
  and confirm that `gh api repos/appliedblockchain/giano/rules/branches/production` shows the ruleset once DevOps has
  applied it.

## 7. Close out

- [ ] 7.1 Mark all six ABIPs as adopted in the summary table of `docs/abip-compliance.md`, with any DevOps-pending
  items called out.
- [ ] 7.2 Run `openspec validate apply-abips --strict`. Then sync the specs and archive the change, in PR 6 or in a
  follow-up if PR 6 is still waiting on DevOps.
- [ ] 7.3 Mark PRs ready and request review through the team's flow (`ae-ask-pr-review`, #giano-dev), bottom-up, only
  when the user asks.
