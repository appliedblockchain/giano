# Proposal

## Why

Dependabot opens weekly version update PRs for both pnpm workspaces and for the GitHub Actions (`.github/dependabot.yml`,
G25 design D6). Notion ticket "Remove the dependabot CI actions and replace with the Toolbox's stale pins action" asks to
replace it with the approach the toolbox repository uses: a weekly run that reports every pin behind its latest
qualifying release in one "Stale pins" issue, and leaves the upgrade to a person.

Dependabot also leaves gaps. It ignores major versions by configuration, so a pin can fall several majors behind with
nothing saying so. It does not cover Node, pnpm, Foundry or the CI tools installed outside npm (Slither, gitleaks,
Trivy); `docs/abip-compliance.md` says these are updated by hand and not checked. Its `services/custom-example` entry
needs a `GH_PACKAGES_READ_TOKEN` secret that was never created (G25 task 2.14).

The toolbox's check (`appliedblockchain/toolbox`, `scripts/repo-checks` and `.github/workflows/freshness.yml`) is not a
reusable action: it is private to that repository and reads its `mise.toml` and Cargo workspace, which Giano does not
have. This change ports it.

## What Changes

- Remove `.github/dependabot.yml`. Dependabot alerts (a repository setting) stay on, and the `dependency-security`
  scenario that compares them with the audit is unchanged.
- Add `scripts/check-stale-pins.mjs`, with unit tests, a dependency-free port of the toolbox's freshness check. It
  compares every exact npm pin in both workspaces, every SHA-pinned action, and Node (`.nvmrc`), pnpm
  (`packageManager`), Foundry, Slither, gitleaks and Trivy with the newest stable release that is at least 7 days old.
  Majors are reported too, labelled as such. Our own `@appliedblockchain/*` pins in `services/custom-example` are
  compared with the version in `packages/*`, so they need no registry token.
- Add `docs/version-deferrals.md`: a pin held back on purpose has a row with a reason, one owner and a review date, as in
  the toolbox. After the review date the pin is reported again.
- Add `.github/workflows/stale-pins.yml`: Mondays and on demand, it runs the check and keeps one issue labelled
  `stale-pins` up to date, or closes it when nothing is stale. It is not a PR check.
- Run the unit tests in the `pinned-versions` job of `ci.yml`.
- Update `docs/abip-compliance.md`, the CodeQL comment and `specs/CI-RELEASE-SPECS.md`, which name Dependabot.
- In the in-flight change `add-ci-security-gates`, remove the requirement "Dependency updates respect the release-age
  window" (it required Dependabot PRs), mark D6 as superseded and drop task 2.14.

## Capabilities

### New Capabilities

- `dependency-freshness`: every pin is compared weekly with its latest qualifying release, and the stale ones are
  reported in one issue.

### Modified Capabilities

None in `openspec/specs`. The requirement removed from `ci-security-gates` exists only in the unarchived change
`add-ci-security-gates`, which is edited in place.

## Impact

- **Workflows.** New `stale-pins.yml` (`contents: read`, `issues: write`). `ci.yml` gains one test step.
- **Process.** No automated upgrade PRs. Someone reads the weekly issue and opens one upgrade PR per pin, as `AGENTS.md`
  requires, or adds a deferral row.
- **Secrets.** `GH_PACKAGES_READ_TOKEN` is no longer needed.
