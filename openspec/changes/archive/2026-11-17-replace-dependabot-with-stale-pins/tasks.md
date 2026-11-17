# Tasks

## 1. Report

- [x] 1.1 Add `scripts/check-stale-pins.mjs` (D1–D5). Verify a local run with `GITHUB_TOKEN` lists every pin kind and
  exits 1 while pins are stale.
- [x] 1.2 Add `scripts/check-stale-pins.test.mjs` covering pin discovery, the 7-day cutoff, grouping, deferrals (exact,
  held major, expired, malformed), our own packages, a failed lookup and the report. Verify all pass.
- [x] 1.3 Add `docs/version-deferrals.md` with an empty table.
- [x] 1.4 Run the unit tests in the `pinned-versions` job of `ci.yml`.

## 2. Workflow and Dependabot

- [x] 2.1 Add `.github/workflows/stale-pins.yml` (D5), with every action pinned by SHA. Verify
  `node scripts/check-ci-gate.mjs` passes.
- [ ] 2.2 After the merge, run it with `workflow_dispatch` and check that it opens the `stale-pins` issue. Record the
  run link in the PR.
- [x] 2.3 Remove `.github/dependabot.yml`. Update `docs/abip-compliance.md`, `codeql.yml` and
  `specs/CI-RELEASE-SPECS.md`.
- [x] 2.4 In `add-ci-security-gates`, remove the requirement "Dependency updates respect the release-age window", mark
  D6 superseded and drop task 2.14.
- [ ] 2.5 After the merge, close the open Dependabot version update PRs, and confirm in the repository settings that
  Dependabot alerts stay on. Decide whether Dependabot security update PRs stay on (a repository setting, not the
  removed file).
