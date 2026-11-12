# Accepted security findings

The CI security checks fail on every finding at or above their gate. A finding the team has assessed and decided not to
fix yet is recorded in [`accepted-findings.json`](accepted-findings.json). This file is the only place a finding can be
accepted. A finding that is not here counts as open, even if a PR description explains it.

`scripts/check-accepted-findings.mjs` reads the register. It runs in CI as job "Accepted-findings register", and each
security check runs it on its own report. The rules are in the `ci-security-gates` capability in OpenSpec.

## Entry fields

```json
{
	"id": "AF-099",
	"tool": "aderyn",
	"match": {
		"detector_name": "yul-return",
		"contract_path": "src/utils/Example.sol",
		"line_no": 12
	},
	"severity": "high",
	"location": "packages/contracts/src/utils/Example.sol:12 (Example constructor)",
	"accepted": "2026-11-09",
	"expires": "2027-05-08",
	"owner": "Rui Sereno",
	"reason": "By design: the constructor returns a value to an eth_call and the contract is never deployed.",
	"followUp": "G22 (independent contract review)."
}
```

| Field | Rule |
|-------|------|
| `id` | `AF-` and three digits. Unique. Take the next free number; never reuse a removed one. |
| `tool` | `slither`, `aderyn`, `pnpm-audit`, `trivy`, `gitleaks` or `codeql`. |
| `match` | The tool's identifier for the finding (next section). It must match exactly. |
| `severity` | `informational`, `low`, `medium`, `moderate`, `high` or `critical`, as the tool reports it. The entry accepts the finding only up to this severity: if the tool later reports it higher, CI fails until the owner reassesses it. |
| `location` | Where the finding is, for a reader: file and line, package and lockfile, or image. |
| `accepted` | The date of the assessment, `YYYY-MM-DD`. |
| `expires` | At most 180 days after `accepted`. Use a shorter date for an entry that only unblocks CI until a fix lands. |
| `owner` | One person, not a team or a list. They reassess the finding before it expires. The check rejects list separators and the words `and`, `or`, `team` and `group`; review catches the rest. |
| `reason` | Why the finding is accepted: false positive, by design, no fix available, or not reachable. Give the evidence. |
| `followUp` | Optional. The ticket or condition that removes the entry. |

## Finding the identifier

Each tool's CI job uploads its full report. Download it from the run's artifacts, or run the tool locally.

| Tool | Gate | `match` | Where to find it |
|------|------|---------|------------------|
| `slither` | High | `check`, `id` | `slither.json`: `results.detectors[].check` and the 64-character `id`. The `id` is a SHA3-256 hash of the finding text, which includes the file and line of the flagged code. An edit that moves that line, a rename, or a Slither upgrade that changes the text format changes the `id` and needs the entry updated. |
| `aderyn` | High | `detector_name`, `contract_path`, `line_no` | `aderyn-report.json`: `high_issues.issues[].detector_name`, and `contract_path` and `line_no` of the instance. Aderyn has no stable finding ID, so an edit above the finding that moves its line needs the entry updated. |
| `pnpm-audit` | high, critical | `workspace` (`.` or `services/custom-example`), `ghsa` | `pnpm audit --json` in that workspace: `advisories.*.github_advisory_id`. |
| `trivy` | HIGH, CRITICAL with a fix | `image`, `package`, `vulnerability` | The image name without registry or tag (`giano-wallet-api`), and `PkgName` and `VulnerabilityID` from the Trivy JSON. |
| `gitleaks` | any | `fingerprint`, or `allowlist` | `Fingerprint` from the gitleaks JSON. An entry for an allowlist in `.gitleaks.toml` uses `{ "allowlist": ".gitleaks.toml" }`, and the allowlist's `description` starts with the entry ID. Each entry accepts one allowlist. |
| `codeql` | checked weekly | `rule`, `alert` | The rule ID and alert number of the dismissed alert in the repository's code scanning alerts. |

Findings below the gate do not fail CI. They stay in the uploaded reports. An open moderate advisory must still be
recorded here (`dependency-security` capability).

## Renewing or removing an entry

When an entry expires, the register check fails on every PR and release until the owner acts:
- **Renew.** Reassess the finding, then set a new `accepted` date, an updated `reason` and a new `expires`.
- **Remove.** If the finding is fixed or no longer reported, delete the entry. Its ID is not reused.

A `slither` or `aderyn` entry that matches no finding in the report fails the job. The PR that fixes or moves a finding
removes or updates its entry. Otherwise a stale `aderyn` entry, which matches only a detector, a file and a line, would
later accept a different finding that lands on the same line. The other tools' findings can change without a code
change, for example when an advisory database changes, so their unused entries do not fail CI.

The weekly security scan lists entries that expire within 14 days.

## What the register check rejects

Register entries:
- A missing or empty field, an unknown field, a duplicate ID, a bad date or an expiry beyond 180 days.
- An expired entry, and an entry whose `accepted` date is after today.

Contract sources and Solidity tool configs:
- A `slither-disable`, `aderyn-ignore` or `aderyn-fp` comment under `packages/contracts/src`. A source comment changes
  the contract metadata hash, and so the bytecode and the CREATE2 addresses.
- A symlink under `packages/contracts/src`, or `src` or a folder above it as a symlink.
- A missing `packages/contracts/slither.config.json` or `packages/contracts/aderyn.toml`, or any change to them other
  than the reasons. They set the scope only: `packages/contracts/src` without `src/testing`. The script compares each
  file with a fixed copy, so a scope change is a change to `scripts/check-accepted-findings.mjs`. The reasons are the
  `//` member of `slither.config.json` and the whole-line `#` comments of `aderyn.toml`. A trailing comment on a
  setting line of `aderyn.toml` fails the check.

gitleaks:
- A `.gitleaks.toml` that does not keep every default rule. It must have `[extend]` with `useDefault = true`, and may
  contain only that, allowlist tables, custom rules and a top-level `title`. Another base config (`path` or `url`) is
  rejected. `disabledRules` is rejected anywhere.
- A `[[rules]]` table whose `id` does not start with `giano-`, appears twice or is missing, or that has no `regex`. A
  custom rule with the ID of a default rule replaces that rule, so the prefix keeps custom rules apart. A custom rule
  may hold only `id`, `description`, `regex` and `keywords`, so it can only add detection. No register entry is needed
  for a rule, because a rule hides nothing.
- An allowlist whose `description` does not start with the ID of a valid, unexpired `gitleaks` entry with
  `{ "allowlist": ".gitleaks.toml" }`, names another ID too, or uses an entry that already accepts another allowlist.
- An allowlist key other than `description` and `regexes`. Keys such as `paths`, `commits`, `stopwords`,
  `regexTarget` or `condition` could widen the allowlist with no change to its register entry.
- TOML that the check cannot read: a quoted table name or key, a multi-line string, an inline table or a dotted
  `allowlist` key. Write each allowlist as an `[allowlist]` or `[[allowlists]]` table.

pnpm:
- A setting that hides advisories (`auditConfig`, `auditLevel`, `ignore`, …) in `pnpm-workspace.yaml`, `.npmrc` or
  `package.json` of either workspace, and a backslash escape in `pnpm-workspace.yaml`, which could hide such a setting.

Files a tool reads by itself to hide findings:
- `packages/contracts/slither.db.json`, `packages/contracts/slither.conf.json`,
  `packages/contracts/export.sarif.sarifexplorer`, `.gitleaksignore`, `.trivyignore`, `.trivyignore.yaml` and
  `trivy.yaml`.
