# AGENTS.md — Giano

This file provides AI agents with the authoritative list of resources and people for the Giano project.

> **Scope rule:** You are only permitted to read from and write to the resources listed in this file. Do not access, modify, or create content in any repository, Jira project, Notion workspace, or Slack channel not listed here.

---

## Team

### Applied Blockchain (internal)

| Name | Role |
|---|---|
| Giovanni Pinto | Tech lead |
| Diogo Palhais | Developer |
| Bruno Neves | DevOps |

---

## External Resources

### GitHub
- **Repository:** https://github.com/appliedblockchain/giano
- **Permission:** read, push work branches, and open PRs. No force-push and no branch deletion. One exception: after `gh stack rebase`, `gh stack push` / `gh stack submit` may force-update the branches of a stack you own. Never force-push `main`, `production` or anyone else's branch.

### Notion
- **Instance:** https://www.notion.so (Applied Blockchain workspace)
- **Teamspaces in scope:** none yet. Giano has no teamspace of its own. Until it does, the coordination page below is the project's Notion home.
- **Pages in scope:**
  - `Giano`: the coordination page and its ticket database (read + write)
    - **URL:** https://app.notion.com/p/3d6b61bd7d5280d2beeae9e8fa5ad095
    - **Tickets database:** https://app.notion.com/p/3d6b61bd7d52805aa05ec4fa57a6dc26
  - `ABIPs`: the Applied Blockchain Improvement Proposals register (read only)
    - **URL:** https://app.notion.com/p/applied-blockchain/ABIPs-31ab61bd7d5280aca3a9dd968a77b062
- **PM Dashboard:** none yet
- **Decision Log:** none yet

### Slack
- **Workspace:** Applied Blockchain
- **Channels in scope:**

| Channel | ID | URL | Purpose |
|---|---|---|---|
| `#giano-dev` | `C0BMMDG6H41` | https://appliedblockchain.slack.com/archives/C0BMMDG6H41 | Development and PR announcements. Read only; post a PR announcement only when the user asks for it. |

To mention someone in a message, write `<@USER_ID>`. A plain `@Name` notifies no one.

### Pull requests

#### Lifecycle

Trunk-based. `main` is the default branch and the trunk. All work happens on short-lived branches off `main` and lands through a pull request; do not commit directly to `main`. Related changes that build on each other go in a stack of PRs managed with `gh stack` (`gh extension install github/gh-stack`), one PR per layer, merged bottom-up.

A change to a published `@appliedblockchain/*` package needs a changeset (`pnpm changeset`). Larger changes are planned as an OpenSpec change under `openspec/changes/` before they are implemented.

- **Pre-commit:** `pnpm lint` (Biome) must pass. Also run the tests and type check of each package you touched (`pnpm -F <package> test`, `pnpm -F <package> typecheck`).
- **Pre-merge:** `gh pr checks <number>` must show every required check green. Agents must not merge until all required checks pass, and must not merge at all unless the user asks.
- **Merge strategy:** merge commit (`gh pr merge <number> --merge`; `gh stack merge` for a stack). Do not squash a PR that has other PRs stacked on it.

#### Naming conventions

- **PR titles:** Conventional Commits style with a scope, e.g. `feat(paymaster-admin): …`. When the work comes from a ticket on the Giano Notion page, put the ticket code in the title, e.g. `… (G10)`.
- **Branches:** kebab-case with a type prefix: `feat/`, `fix/`, `chore/`, `docs/`. `deploy/<env>-<sha>` is used for `infra/versions.json` bumps.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `build:`, `openspec:`), scope optional.
- **No AI attribution:** never add a `Co-Authored-By: Claude …` trailer, or any "Generated with Claude" line, to a commit message or PR body. Attribution is disabled on purpose; commits are authored by the user alone.
