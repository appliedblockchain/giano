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
| `severity` | `informational`, `low`, `medium`, `moderate`, `high` or `critical`, as the tool reports it. |
| `location` | Where the finding is, for a reader: file and line, package and lockfile, or image. |
| `accepted` | The date of the assessment, `YYYY-MM-DD`. |
| `expires` | At most 180 days after `accepted`. Use a shorter date for an entry that only unblocks CI until a fix lands. |
| `owner` | One person, not a team. They reassess the finding before it expires. |
| `reason` | Why the finding is accepted: false positive, by design, no fix available, or not reachable. Give the evidence. |
| `followUp` | Optional. The ticket or condition that removes the entry. |

## Finding the identifier

Each tool's CI job uploads its full report. Download it from the run's artifacts, or run the tool locally.

| Tool | Gate | `match` | Where to find it |
|------|------|---------|------------------|
| `slither` | High | `check`, `id` | `slither.json`: `results.detectors[].check` and the 64-character `id`. The `id` depends on the code and the Slither version, so a change to the flagged code or a Slither upgrade needs the entry updated. |
| `aderyn` | High | `detector_name`, `contract_path`, `line_no` | `aderyn-report.json`: `high_issues.issues[].detector_name`, and `contract_path` and `line_no` of the instance. Aderyn has no stable finding ID, so an edit above the finding that moves its line needs the entry updated. |
| `pnpm-audit` | high, critical | `workspace` (`.` or `services/custom-example`), `ghsa` | `pnpm audit --json` in that workspace: `advisories.*.github_advisory_id`. |
| `trivy` | HIGH, CRITICAL with a fix | `image`, `package`, `vulnerability` | The image name without registry or tag (`giano-wallet-api`), and `PkgName` and `VulnerabilityID` from the Trivy JSON. |
| `gitleaks` | any | `fingerprint`, or `allowlist` | `Fingerprint` from the gitleaks JSON. An entry for an allowlist in `.gitleaks.toml` uses `{ "allowlist": ".gitleaks.toml" }`, and the allowlist's `description` names the entry ID. |
| `codeql` | checked weekly | `rule`, `alert` | The rule ID and alert number of the dismissed alert in the repository's code scanning alerts. |

Findings below the gate do not fail CI. They stay in the uploaded reports. An open moderate advisory must still be
recorded here (`dependency-security` capability).

## Renewing or removing an entry

When an entry expires, the register check fails on every PR and release until the owner acts:
- **Renew.** Reassess the finding, then set a new `accepted` date, an updated `reason` and a new `expires`.
- **Remove.** If the finding is fixed or no longer reported, delete the entry. Its ID is not reused.

The weekly security scan lists entries that expire within 14 days.

## What the register check rejects

- A missing or empty field, an unknown field, a duplicate ID, a bad date or an expiry beyond 180 days.
- An expired entry, and an entry whose `accepted` date is after today.
- A `slither-disable`, `aderyn-ignore` or `aderyn-fp` comment under `packages/contracts/src`. A source comment changes
  the contract metadata hash, and so the bytecode and the CREATE2 addresses.
- A detector setting in `packages/contracts/slither.config.json` or `packages/contracts/aderyn.toml`. These files set
  scope only: dependencies, tests, scripts and `src/testing` are outside the analysis. `aderyn.toml` may contain only
  the top-level keys `version`, `root`, `src`, `include` and `exclude`, each on one line.
- A gitleaks allowlist whose `description` does not name a valid, unexpired `gitleaks` entry with
  `{ "allowlist": ".gitleaks.toml" }`, and any `disabledRules`.
- A `.gitleaks.toml` that does not keep every default rule. It must have `[extend]` with `useDefault = true`, and may
  contain only that, allowlist tables and a top-level `title`. Another base config (`path` or `url`) and custom
  `[[rules]]` are rejected, because they can replace or weaken a default rule.
- TOML that the check cannot read: a quoted table name or key, or a multi-line string. In `.gitleaks.toml`, also an
  inline table or a dotted `allowlist` key. Write each allowlist as an `[allowlist]` or `[[allowlists]]` table.
- A file a tool reads by itself to hide findings: `packages/contracts/slither.db.json`,
  `packages/contracts/export.sarif.sarifexplorer` and `.gitleaksignore`.
