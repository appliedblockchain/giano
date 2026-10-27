## Purpose

Code reaches Giano's production environment only from a protected `production` branch that requires reviewed pull
requests, while development continues on `main`. This is the repository's implementation of ABIP-1.

## ADDED Requirements

### Requirement: A protected production branch exists and is not the default
The repository SHALL have a branch named `production`. `main` SHALL remain the default branch. A branch ruleset on
`production` SHALL enforce three rules:
- changes arrive only through a pull request;
- at least one approving review is required;
- the rules apply with no bypass, administrators included.

The tech lead MAY add further rules.

#### Scenario: Direct push refused
- **WHEN** anyone, an administrator included, pushes a commit directly to `production`
- **THEN** GitHub rejects the push

#### Scenario: Unreviewed PR cannot merge
- **WHEN** a pull request into `production` has no approving review
- **THEN** it cannot be merged

#### Scenario: Default branch unchanged
- **WHEN** the repository settings are read
- **THEN** the default branch is `main`

### Requirement: Production deploys only from the production branch
Rollouts to the `prd` environment SHALL be triggered only by a change to `infra/versions.json` on `production`, or by a
manual dispatch run from `production`. A change to `prd` in `infra/versions.json` on `main` SHALL deploy nothing. The
`prd` tag SHALL be the SHA of a commit reachable from `production`. `dev` and `stg` SHALL keep deploying from `main`.

#### Scenario: Prd bump merged on main
- **WHEN** a commit on `main` changes `.prd` in `infra/versions.json`
- **THEN** the deploy workflow rolls no `prd` service, and reports that `prd` deploys from `production`

#### Scenario: Prd bump promoted to production
- **WHEN** a reviewed PR into `production` changes `.prd` to a commit SHA reachable from `production`
- **THEN** the deploy workflow rolls every `prd` service to that tag

#### Scenario: Prd tag not on production
- **WHEN** `.prd` on `production` names a SHA that is not an ancestor of the `production` head
- **THEN** the deploy workflow fails before assuming the deploy role, and names the SHA

#### Scenario: Dispatch for prd from main
- **WHEN** a manual dispatch for `prd` is started from `main`
- **THEN** it fails without deploying

### Requirement: The production cloud role trusts only the production branch
The AWS OIDC deploy role for `prd` SHALL accept GitHub tokens only for `ref:refs/heads/production`. The `dev` and `stg`
roles SHALL keep their current trusted refs.

#### Scenario: Main workflow cannot assume the prd role
- **WHEN** a workflow running on `main` requests the `giano-prd-gha-deploy` role
- **THEN** AWS STS refuses it

### Requirement: Promotion to production is a reviewed merge of main
The `prd` bump in `infra/versions.json` SHALL first be merged into `main` through a reviewed PR. That merge deploys
nothing to prd. The bump then reaches `production` through a pull request from `main` into `production`, which SHALL be
merged with a merge commit and SHALL pass the same required checks as `main`. A hotfix SHALL land on `main` first and
then be promoted the same way. Every non-merge commit on `production` SHALL be reachable from `main`. The procedure
SHALL be documented in `AGENTS.md` and `specs/INFRASTRUCTURE.md` §15.

#### Scenario: Normal promotion
- **WHEN** a PR from `main` into `production` is approved and merged, and it carries a `.prd` change
- **THEN** the deploy workflow on `production` rolls prd to the new tag

#### Scenario: Production drifts ahead of main
- **WHEN** `production` contains a non-merge commit that is not reachable from `main`
- **THEN** the documented procedure requires a merge-back PR into `main` before the next promotion

### Requirement: Compliance is recorded
`docs/abip-compliance.md` SHALL record ABIP-1: the branch name, the ruleset settings, who holds the right to change the
ruleset, and that prd is the only environment that deploys from `production`.

#### Scenario: Auditor checks ABIP-1
- **WHEN** an ISO 27001 auditor reads `docs/abip-compliance.md`
- **THEN** it states the protected branch, the review rule, the no-bypass setting and the prd deploy path
