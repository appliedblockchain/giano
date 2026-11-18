# Design

## D1. Port, not reuse

The toolbox's check reads its own repository layout (`mise.toml`, Cargo, its registers module), and the toolbox is
private, so Giano cannot call it. The port keeps its rules (latest qualifying release, deferral table, one issue) and
its source lookups (npm registry `time`, GitHub releases, PyPI first upload, Node release schedule), and drops what Giano
has no use for (mise, Cargo, the library Node floor, peer ranges). It follows the other `scripts/check-*.mjs`: one
dependency-free ES module with exported functions and a `node --test` file. The release-age window is imported from
`check-release-age.mjs`, so the two checks cannot disagree.

## D2. What is a pin

- **npm:** exact versions (and `npm:` aliases) in `dependencies`, `devDependencies` and `optionalDependencies` of every
  tracked `package.json`, outside `vendor/` and `packages/contracts/lib/`. Not `overrides`: they are security floors
  that the dependency audit owns. Not peer ranges, which ABIP-7 lets the published libraries keep.
- **Our own packages:** a pin on a package of this repository is checked only in `services/custom-example`, against
  the `version` in `packages/*/package.json`, which `release.yml` publishes. No GitHub Packages token is needed.
- **Actions:** `uses: owner/repo[/path]@<40-hex SHA> # vX.Y.Z`, against the repository's GitHub releases. For a stale
  action the report gives the commit SHA of the newer tag, since that is what the workflow pins.
- **Tools:** a fixed table (`TOOLS`) of file globs and patterns: `.nvmrc` (Node, newest release of the newest Active
  LTS line), `packageManager` (pnpm), Foundry in the workflows, the compose files and `e2e/devnet/generate-state.mjs`,
  `GITLEAKS_VERSION`, `*TRIVY_VERSION` and `slither-analyzer==`. A tool pinned in several places is checked in each, so a
  missed copy shows up as its own row.

## D3. Qualifying release and update type

The newest stable release (no pre-release part) published at least 7 days ago (ABIP-6). Unlike Dependabot's
configuration, majors count: the report has an "Update" column (`major`, `minor`, `patch`) so a reader can tell routine
bumps from upgrades that need their own review.

## D4. Deferrals

`docs/version-deferrals.md` is a Markdown table with the toolbox's columns: Name, Held version, Reason, Owner,
Review-by. A held version is exact (`3.24.4`) or a major (`4.x`); a major still expects the newest release within it,
so `actions/upload-artifact` held at `4.x` is reported when 4.6.3 ships. A row past its review date holds nothing. A
malformed row is reported and holds nothing.

## D5. The report and the issue

The script prints Markdown and exits 1 if any pin is stale, any lookup failed or any deferral row is broken; a failed
lookup is never reported as current. `stale-pins.yml` writes the report to the job summary and to one open issue
labelled `stale-pins`, created or edited in place, and closes it on a clean run. Any other exit fails the job without
touching the issue. The run is not a PR check, so a new upstream release cannot block an unrelated PR. It runs at
07:00 UTC on Mondays, an hour after `security-scan.yml`, with `GITHUB_TOKEN` for the GitHub API rate limit.

## D6. What is not covered

Container images pinned by digest (DHI bases and compose images) are not compared with newer tags: their freshness is
the DHI refresh and the Trivy scan (ABIP-2). The pip lock file `requirements-ci.txt` is not compared entry by entry;
only the top-level Slither pin is. Both were outside Dependabot too.
