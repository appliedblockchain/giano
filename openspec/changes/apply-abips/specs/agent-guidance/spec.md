## Purpose

Gives AI coding agents one authoritative, in-repository source for Giano's team, the external systems in scope and what
an agent may do in each, and the pull-request conventions. This is the repository's implementation of ABIP-5.

## ADDED Requirements

### Requirement: AGENTS.md exists at the repository root and follows the ABIP-5 template
The repository SHALL have an `AGENTS.md` at its root. It SHALL use the ABIP-5 template's headings in the template's
order: title, scope rule, `## Team`, `## External Resources` with its system subsections, and `### Pull requests`. A
section that does not apply to Giano MAY be omitted. Every section that is present SHALL keep the template's structure
and required fields:

| Section | Required fields |
|---------|-----------------|
| GitHub | repository URL |
| Jira | board URL, cloud ID, project key |
| Notion | teamspace name, ID and URL; Decision Log URL |
| Slack | a table row for each channel, with name, ID, URL and purpose |
| Pull requests | lifecycle, pre-commit, pre-merge, merge strategy, and naming conventions for PR titles, branches and commits |

#### Scenario: Required fields present
- **WHEN** `AGENTS.md` contains a `### Slack` section
- **THEN** every channel listed in it has a name, an ID, a URL and a purpose

#### Scenario: Non-applicable section omitted
- **WHEN** Giano has no Jira project
- **THEN** `AGENTS.md` has no `### Jira` section, and none of its other sections names a Jira key

### Requirement: The scope rule and per-system permissions are explicit
`AGENTS.md` SHALL open with the ABIP-5 scope rule: an agent may read and write only the resources listed in the file.
Each external system section SHALL state the agent's permission, using the ABIP-5 default unless the team has recorded
a narrower one:

| System | Default permission |
|--------|--------------------|
| GitHub | read and open PRs; no force-push and no branch deletion |
| Notion | read and write within the named teamspaces |
| Slack | read only, no posting |

If posting to a Slack channel is allowed, the section SHALL say so for that channel by name.

#### Scenario: Agent asked to post in an unlisted channel
- **WHEN** an agent working in this repository is asked to post in a Slack channel that `AGENTS.md` does not list
- **THEN** the file's scope rule forbids it, and the agent declines or asks

### Requirement: The pull-request section documents the conventions the team actually enforces
The `### Pull requests` section SHALL describe the conventions that are enforced or expected in this repository, and no
other project's:
- the branching model: work branches off `main`, with `production` as the protected release branch once ABIP-1 lands;
- the pre-commit command (`pnpm lint`, which is Biome);
- the pre-merge check (`gh pr checks`, which must be all green; agents never merge on red);
- the merge strategy;
- the naming conventions for PR titles, branches (`feat/`, `fix/`, `chore/`, `docs/`) and commits (Conventional
  Commits);
- the rule that commits and PR bodies carry no AI attribution trailer.

When one of these conventions changes, `AGENTS.md` SHALL be updated in the same PR.

#### Scenario: Attribution rule survives the move
- **WHEN** an agent reads the repository's instructions after the change
- **THEN** it finds the rule that commits and PR bodies carry no `Co-Authored-By: Claude` trailer or "Generated with
  Claude" line, in `AGENTS.md`

#### Scenario: Convention change without an AGENTS.md update
- **WHEN** a PR changes the release-branch model, for example by adding the ABIP-1 `production` branch
- **THEN** the same PR updates the lifecycle in `AGENTS.md`

### Requirement: CLAUDE.md imports AGENTS.md
`CLAUDE.md` at the repository root SHALL contain the line `@AGENTS.md`. It SHALL NOT duplicate content that `AGENTS.md`
holds.

#### Scenario: Claude Code session start
- **WHEN** Claude Code opens a session at the repository root
- **THEN** it loads `AGENTS.md` through the `@AGENTS.md` import in `CLAUDE.md`

### Requirement: No secrets in agent guidance
`AGENTS.md` and `CLAUDE.md` SHALL NOT contain credentials, tokens, private keys, API keys or secret values. Identifiers
that are not secrets are allowed: URLs, Slack channel IDs, Notion teamspace IDs and a Jira cloud ID.

#### Scenario: Secret scan
- **WHEN** the files are scanned for key-shaped material, such as 32-byte hex strings, `ghp_` or `xox` prefixes, or PEM
  headers
- **THEN** nothing is found
