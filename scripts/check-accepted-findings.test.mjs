import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";

import {
	checkAderynConfig,
	checkGitleaksConfig,
	checkRepository,
	checkSlitherConfig,
	evaluateReport,
	findInSourceSuppressions,
	main,
	ReportError,
	validateRegister,
} from "./check-accepted-findings.mjs";

const TODAY = "2026-11-09";
const SLITHER_ID =
	"73b125f9973ab8392f7bb64dadb71f1b6fa569496f34d7d6e787d55049ed4891";

const entry = (overrides = {}) => ({
	id: "AF-001",
	tool: "slither",
	match: { check: "arbitrary-send-eth", id: SLITHER_ID },
	severity: "high",
	location: "packages/contracts/src/GianoSmartWallet.sol#L299-L306",
	accepted: "2026-11-09",
	expires: "2027-05-08",
	owner: "Sarah Thompson",
	reason: "False positive: every caller is access controlled.",
	...overrides,
});
const register = (...entries) => ({ entries });
const rules = (errs) => errs.map((e) => e.rule);

describe("check-accepted-findings: register", () => {
	it("passes a valid entry, with expiry exactly 180 days after acceptance", () => {
		assert.deepEqual(validateRegister(register(entry()), TODAY), []);
	});

	it("rejects an entry with an empty owner and names the entry and the field", () => {
		const errs = validateRegister(register(entry({ owner: "" })), TODAY);
		assert.deepEqual(rules(errs), ["missing-field"]);
		assert.equal(errs[0].entry, "AF-001");
		assert.match(errs[0].message, /owner/);
	});

	it("rejects each missing required field", () => {
		const { reason, location, ...rest } = entry();
		assert.deepEqual(rules(validateRegister(register(rest), TODAY)), [
			"missing-field",
			"missing-field",
		]);
	});

	it("rejects an expiry more than 180 days after acceptance", () => {
		const errs = validateRegister(
			register(entry({ expires: "2027-12-01" })),
			TODAY,
		);
		assert.deepEqual(rules(errs), ["expiry-too-far"]);
	});

	it("rejects an expiry before the accepted date", () => {
		assert.deepEqual(
			rules(
				validateRegister(register(entry({ expires: "2026-11-08" })), TODAY),
			),
			["expiry-before-accepted", "expired"],
		);
	});

	it("fails an expired entry and names its owner and expiry date", () => {
		const errs = validateRegister(register(entry()), "2027-05-09");
		assert.deepEqual(rules(errs), ["expired"]);
		assert.equal(errs[0].entry, "AF-001");
		assert.match(errs[0].message, /2027-05-08/);
		assert.match(errs[0].message, /Sarah Thompson/);
	});

	it("still passes on the expiry date itself", () => {
		assert.deepEqual(validateRegister(register(entry()), "2027-05-08"), []);
	});

	it("passes again after renewal with a new accepted date and expiry", () => {
		const renewed = entry({
			accepted: "2027-05-09",
			expires: "2027-11-01",
			reason: "Reassessed: still a false positive.",
		});
		assert.deepEqual(validateRegister(register(renewed), "2027-05-09"), []);
	});

	it("rejects a duplicate ID", () => {
		const errs = validateRegister(
			register(entry(), entry({ match: { check: "x", id: "0".repeat(64) } })),
			TODAY,
		);
		assert.deepEqual(rules(errs), ["duplicate-id"]);
	});

	it("rejects a malformed ID, an unknown field and an unknown tool", () => {
		assert.deepEqual(
			rules(validateRegister(register(entry({ id: "AF-1" })), TODAY)),
			["bad-id"],
		);
		assert.deepEqual(
			rules(validateRegister(register(entry({ note: "x" })), TODAY)),
			["unknown-field"],
		);
		assert.deepEqual(
			rules(validateRegister(register(entry({ tool: "semgrep" })), TODAY)),
			["bad-tool"],
		);
	});

	it("rejects a match that does not fit the tool's finding identifier", () => {
		assert.deepEqual(
			rules(
				validateRegister(
					register(entry({ match: { check: "arbitrary-send-eth" } })),
					TODAY,
				),
			),
			["bad-match"],
		);
		assert.deepEqual(
			rules(
				validateRegister(
					register(
						entry({
							tool: "pnpm-audit",
							match: {
								workspace: "services/wallet-api",
								ghsa: "GHSA-g3hv-75wg-m249",
							},
						}),
					),
					TODAY,
				),
			),
			["bad-match"],
		);
	});

	it("accepts the match shape of every tool", () => {
		const matches = {
			aderyn: {
				detector_name: "yul-return",
				contract_path: "src/utils/ERC1271InputGenerator.sol",
				line_no: 48,
			},
			"pnpm-audit": { workspace: ".", ghsa: "GHSA-g3hv-75wg-m249" },
			trivy: {
				image: "giano-wallet-api",
				package: "openssl",
				vulnerability: "CVE-2026-0001",
			},
			gitleaks: { fingerprint: "abc:file:rule:1" },
			codeql: { rule: "js/path-injection", alert: 12 },
		};
		for (const [tool, match] of Object.entries(matches))
			assert.deepEqual(
				validateRegister(register(entry({ tool, match })), TODAY),
				[],
				tool,
			);
		assert.deepEqual(
			validateRegister(
				register(
					entry({ tool: "gitleaks", match: { allowlist: ".gitleaks.toml" } }),
				),
				TODAY,
			),
			[],
		);
	});

	it("rejects an impossible date and an owner that names more than one person", () => {
		assert.deepEqual(
			rules(
				validateRegister(register(entry({ accepted: "2026-02-30" })), TODAY),
			),
			["bad-date"],
		);
		assert.deepEqual(
			rules(
				validateRegister(
					register(entry({ owner: "Sarah Thompson and John Smith" })),
					TODAY,
				),
			),
			["bad-owner"],
		);
	});

	it("rejects a register without an entries array", () => {
		assert.deepEqual(rules(validateRegister([entry()], TODAY)), [
			"bad-register",
		]);
	});
});

describe("check-accepted-findings: suppressions", () => {
	it("rejects slither-disable, aderyn-ignore and aderyn-fp comments in contract source, with file and line", () => {
		const errs = findInSourceSuppressions([
			{
				file: "packages/contracts/src/A.sol",
				text: "contract A {\n  // slither-disable-next-line arbitrary-send-eth\n  // aderyn-ignore-next-line(yul-return)\n  // aderyn-fp-next-line\n}",
			},
		]);
		assert.deepEqual(
			errs.map((e) => [e.file, e.line, e.rule]),
			[
				["packages/contracts/src/A.sol", 2, "in-source-suppression"],
				["packages/contracts/src/A.sol", 3, "in-source-suppression"],
				["packages/contracts/src/A.sol", 4, "in-source-suppression"],
			],
		);
	});

	it("fails a gitleaks allowlist without a register entry ID, naming the file and block", () => {
		const toml =
			'[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "Anvil keys"\nregexes = ["0xac09"]\n';
		const errs = checkGitleaksConfig(toml, new Set(["AF-008"]));
		assert.deepEqual(rules(errs), ["suppression-without-entry"]);
		assert.equal(errs[0].file, ".gitleaks.toml");
		assert.equal(errs[0].line, 4);
	});

	it("fails a gitleaks allowlist that names an entry that does not exist", () => {
		const toml = '[[allowlists]]\ndescription = "AF-009: Anvil keys"\n';
		assert.match(
			checkGitleaksConfig(toml, new Set(["AF-008"]))[0].message,
			/\(AF-009 is not one\)/,
		);
	});

	it("passes a gitleaks allowlist that names an entry, and rejects disabledRules", () => {
		const ok =
			'[[allowlists]]\ndescription = "AF-008: public Anvil development keys"\n';
		assert.deepEqual(checkGitleaksConfig(ok, new Set(["AF-008"])), []);
		const disabled =
			'[extend]\nuseDefault = true\ndisabledRules = ["generic-api-key"]\n';
		assert.deepEqual(rules(checkGitleaksConfig(disabled, new Set())), [
			"config-suppression",
		]);
	});

	it("allows scope keys in slither.config.json and rejects detector suppressions", () => {
		const scope = JSON.stringify({
			"//": ["reason"],
			filter_paths: "lib",
			exclude_informational: true,
			exclude_optimization: true,
		});
		assert.deepEqual(checkSlitherConfig(scope), []);
		assert.deepEqual(
			rules(
				checkSlitherConfig(
					JSON.stringify({ detectors_to_exclude: "arbitrary-send-eth" }),
				),
			),
			["config-suppression"],
		);
		assert.deepEqual(
			rules(checkSlitherConfig(JSON.stringify({ exclude_high: true }))),
			["config-suppression"],
		);
		assert.deepEqual(rules(checkSlitherConfig("{")), ["invalid-config"]);
	});

	it("allows only the top-level scope keys in aderyn.toml", () => {
		const scope =
			'# reason\nversion = 1\nroot = "." # comment\nsrc = "src"\nexclude = ["src/testing/", "a # b"]\n';
		assert.deepEqual(checkAderynConfig(scope), []);
		const errs = checkAderynConfig(
			'version = 1\n[detectors]\nexclude = ["yul-return"]\n',
		);
		assert.deepEqual(
			errs.map((e) => [e.line, e.rule]),
			[
				[2, "config-suppression"],
				[3, "config-suppression"],
			],
		);
	});

	it("rejects every other TOML form in aderyn.toml that could set detectors", () => {
		for (const [toml, rule] of [
			["[detectors]\n", "config-suppression"],
			['["detectors"]\n', "unsupported-config"],
			["detectors.yul-return = false\n", "config-suppression"],
			["detectors = { yul-return = false }\n", "config-suppression"],
			['"src" = "src"\n', "unsupported-config"],
			['src = { path = "src" }\n', "config-suppression"],
			['exclude = [\n  "src/testing/",\n]\n', "unsupported-config"],
			["src = '''\nsrc'''\n", "unsupported-config"],
		])
			assert.equal(checkAderynConfig(toml)[0]?.rule, rule, toml);
	});

	it("rejects every other TOML form in .gitleaks.toml that could hide a finding", () => {
		const ids = new Set(["AF-008"]);
		for (const [toml, rule] of [
			['["allowlist"]\ndescription = "AF-008"\n', "unsupported-config"],
			["[ 'rules' . allowlists ]\n", "unsupported-config"],
			['allowlist.paths = ["x"]\n', "unsupported-config"],
			['allowlist = { paths = ["x"] }\n', "unsupported-config"],
			[
				'[[rules]]\nid = "x"\nallowlists = [{ paths = ["x"] }]\n',
				"unsupported-config",
			],
			[
				'rules = [\n  { id = "x", allowlist = { paths = ["x"] } },\n]\n',
				"unsupported-config",
			],
			['[allowlist.extra]\npaths = ["x"]\n', "unsupported-config"],
			['extend.disabledRules = ["generic-api-key"]\n', "config-suppression"],
			["[allowlist]\ndescription = '''\nAF-008'''\n", "unsupported-config"],
		])
			assert.ok(rules(checkGitleaksConfig(toml, ids)).includes(rule), toml);
		const ok =
			"[extend]\nuseDefault = true\n\n[ rules . allowlists ]\ndescription = \"AF-008\" # c\nregexes = ['''0x[a-f]{64}''']\n";
		assert.deepEqual(checkGitleaksConfig(ok, ids), []);
	});
});

describe("check-accepted-findings: repository check", () => {
	const root = mkdtempSync(join(tmpdir(), "accepted-findings-"));
	after(() => rmSync(root, { recursive: true, force: true }));
	const write = (file, text) => {
		mkdirSync(dirname(join(root, file)), { recursive: true });
		writeFileSync(join(root, file), text);
	};

	it("fails when the register is missing", () => {
		assert.deepEqual(rules(checkRepository(root, TODAY)), ["missing-register"]);
	});

	it("passes a clean repository and fails on each kind of problem", () => {
		write("security/accepted-findings.json", JSON.stringify(register(entry())));
		write("packages/contracts/src/sub/A.sol", "contract A {}\n");
		write(
			"packages/contracts/slither.config.json",
			JSON.stringify({ filter_paths: "lib" }),
		);
		assert.deepEqual(checkRepository(root, TODAY), []);

		write(
			"packages/contracts/src/sub/B.sol",
			"contract B {\n// slither-disable-next-line x\n}\n",
		);
		write("packages/contracts/slither.db.json", "[]");
		write(".gitleaks.toml", '[[allowlists]]\ndescription = "no entry"\n');
		const errs = checkRepository(root, "2027-05-09");
		assert.deepEqual(rules(errs).sort(), [
			"expired",
			"in-source-suppression",
			"suppression-file",
			"suppression-without-entry",
		]);
		assert.ok(
			errs.some(
				(e) => e.file === "packages/contracts/src/sub/B.sol" && e.line === 2,
			),
		);
	});

	it("validates a register that parses to null, false, 0 or an empty string", () => {
		const dir = mkdtempSync(join(tmpdir(), "accepted-findings-falsy-"));
		try {
			mkdirSync(join(dir, "security"));
			for (const value of ["null", "false", "0", '""']) {
				writeFileSync(join(dir, "security/accepted-findings.json"), value);
				assert.deepEqual(rules(checkRepository(dir, TODAY)), ["bad-register"]);
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("lets a gitleaks allowlist cite only a usable gitleaks entry for .gitleaks.toml", () => {
		const dir = mkdtempSync(join(tmpdir(), "accepted-findings-allowlist-"));
		try {
			mkdirSync(join(dir, "security"));
			writeFileSync(
				join(dir, ".gitleaks.toml"),
				'[[allowlists]]\ndescription = "AF-008: public Anvil keys"\n',
			);
			const check = (...entries) => {
				writeFileSync(
					join(dir, "security/accepted-findings.json"),
					JSON.stringify(register(...entries)),
				);
				return rules(checkRepository(dir, TODAY));
			};
			const gitleaks = (match) =>
				entry({ id: "AF-008", tool: "gitleaks", match, severity: "high" });
			assert.deepEqual(check(gitleaks({ allowlist: ".gitleaks.toml" })), []);
			assert.deepEqual(check(entry({ id: "AF-008" })), [
				"suppression-without-entry",
			]);
			assert.deepEqual(check(gitleaks({ fingerprint: "a:b:c:1" })), [
				"suppression-without-entry",
			]);
			assert.deepEqual(
				check(
					gitleaks({ allowlist: ".gitleaks.toml" }),
					gitleaks({ allowlist: ".gitleaks.toml" }),
				).sort(),
				["duplicate-id", "suppression-without-entry"],
			);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

// --- Report mode -----------------------------------------------------------------------------

const slitherReport = (detectors) =>
	JSON.stringify({ success: true, error: null, results: { detectors } });
const slitherHigh = {
	check: "arbitrary-send-eth",
	id: SLITHER_ID,
	impact: "High",
	first_markdown_element: "src/GianoSmartWallet.sol#L299-L306",
};
const aderynReport = (high, low = []) =>
	JSON.stringify({
		high_issues: { issues: high },
		low_issues: { issues: low },
	});
const aderynHigh = {
	detector_name: "yul-return",
	instances: [
		{ contract_path: "src/utils/ERC1271InputGenerator.sol", line_no: 48 },
	],
};
const aderynEntry = entry({
	id: "AF-005",
	tool: "aderyn",
	match: {
		detector_name: "yul-return",
		contract_path: "src/utils/ERC1271InputGenerator.sol",
		line_no: 48,
	},
});
const auditReport = (advisories) =>
	JSON.stringify({ advisories, metadata: { vulnerabilities: {} } });
const advisory = (severity, ghsa = "GHSA-g3hv-75wg-m249") => ({
	1: { id: 1, module_name: "minimatch", severity, github_advisory_id: ghsa },
});
const auditEntry = entry({
	id: "AF-006",
	tool: "pnpm-audit",
	severity: "high",
	match: { workspace: ".", ghsa: "GHSA-g3hv-75wg-m249" },
});
const trivyReport = (vulns) =>
	JSON.stringify({
		SchemaVersion: 2,
		ArtifactName: "image.tar",
		Results: [{ Target: "debian", Vulnerabilities: vulns }],
	});
const trivyVuln = (overrides = {}) => ({
	VulnerabilityID: "CVE-2026-0001",
	PkgName: "openssl",
	InstalledVersion: "3.0.0",
	FixedVersion: "3.0.1",
	Severity: "CRITICAL",
	...overrides,
});
const trivyEntry = entry({
	id: "AF-010",
	tool: "trivy",
	severity: "critical",
	match: {
		image: "giano-wallet-api",
		package: "openssl",
		vulnerability: "CVE-2026-0001",
	},
});
const leak = {
	RuleID: "private-key",
	File: "keys.txt",
	StartLine: 3,
	Commit: "0123456789abcdef0123",
	Secret: "SUPERSECRETVALUE",
	Fingerprint: "0123456789abcdef0123:keys.txt:private-key:3",
};
const leakEntry = entry({
	id: "AF-011",
	tool: "gitleaks",
	match: { fingerprint: leak.Fingerprint },
});

// Each tool: a report with one gating finding, the entry that accepts it, and an invalid report.
const CASES = {
	slither: {
		report: slitherReport([slitherHigh]),
		entry: entry(),
		invalid: JSON.stringify({
			success: false,
			error: "compilation failed",
			results: {},
		}),
	},
	aderyn: {
		report: aderynReport([aderynHigh]),
		entry: aderynEntry,
		invalid: JSON.stringify({ files_summary: {} }),
	},
	"pnpm-audit": {
		report: auditReport(advisory("high")),
		entry: auditEntry,
		invalid: JSON.stringify({
			error: {
				code: "ERR_PNPM_AUDIT_BAD_RESPONSE",
				message: "registry returned 503",
			},
		}),
		options: { workspace: "." },
	},
	trivy: {
		report: trivyReport([trivyVuln()]),
		entry: trivyEntry,
		invalid: JSON.stringify({ Results: [] }),
		options: { image: "giano-wallet-api" },
	},
	gitleaks: {
		report: JSON.stringify([leak]),
		entry: leakEntry,
		invalid: JSON.stringify({ findings: [] }),
	},
};

for (const [tool, c] of Object.entries(CASES)) {
	describe(`check-accepted-findings: ${tool} report`, () => {
		const run = (text, reg, today = TODAY) =>
			evaluateReport(tool, text, reg, today, c.options);

		it("accepts a finding that matches a valid entry and names the entry", () => {
			const result = run(c.report, register(c.entry));
			assert.deepEqual(result.failures, []);
			assert.deepEqual(
				result.accepted.map((a) => a.entry),
				[c.entry.id],
			);
		});

		it("fails a finding with no entry", () => {
			const result = run(c.report, register());
			assert.equal(result.failures.length, 1);
			assert.match(result.failures[0].message, /no entry/);
		});

		it("fails a finding whose entry has expired", () => {
			const result = run(c.report, register(c.entry), "2027-05-09");
			assert.equal(result.failures.length, 1);
			assert.match(
				result.failures[0].message,
				new RegExp(
					`matches ${c.entry.id}, but the entry expired on 2027-05-08`,
				),
			);
		});

		it("fails a finding whose only matching entry is not valid", () => {
			const result = run(c.report, register({ ...c.entry, owner: "" }));
			assert.match(result.failures[0].message, /not valid/);
		});

		it("fails an invalid, empty or non-JSON report", () => {
			for (const text of [c.invalid, "", "   \n", "not json"])
				assert.throws(
					() => run(text, register(c.entry)),
					ReportError,
					JSON.stringify(text),
				);
		});
	});
}

describe("check-accepted-findings: report details", () => {
	it("does not gate Slither Medium findings", () => {
		const result = evaluateReport(
			"slither",
			slitherReport([{ ...slitherHigh, impact: "Medium" }]),
			register(),
			TODAY,
		);
		assert.deepEqual(result, { accepted: [], failures: [], belowGate: 1 });
	});

	it("passes a Slither report with no detectors", () => {
		assert.deepEqual(
			evaluateReport(
				"slither",
				JSON.stringify({ success: true, error: null, results: {} }),
				register(),
				TODAY,
			).failures,
			[],
		);
	});

	it("does not gate Aderyn low issues, and needs path and line to match", () => {
		const low = evaluateReport(
			"aderyn",
			aderynReport([], [aderynHigh]),
			register(),
			TODAY,
		);
		assert.deepEqual(low.failures, []);
		assert.equal(low.belowGate, 1);
		const moved = {
			...aderynHigh,
			instances: [
				{ contract_path: "src/utils/ERC1271InputGenerator.sol", line_no: 49 },
			],
		};
		assert.equal(
			evaluateReport(
				"aderyn",
				aderynReport([moved]),
				register(aderynEntry),
				TODAY,
			).failures.length,
			1,
		);
	});

	it("gates pnpm high and critical, lists accepted moderates, and scopes entries to the workspace", () => {
		const moderate = evaluateReport(
			"pnpm-audit",
			auditReport(advisory("moderate")),
			register(),
			TODAY,
			{ workspace: "." },
		);
		assert.deepEqual(moderate.failures, []);
		const accepted = evaluateReport(
			"pnpm-audit",
			auditReport(advisory("moderate")),
			register(auditEntry),
			TODAY,
			{
				workspace: ".",
			},
		);
		assert.deepEqual(
			accepted.accepted.map((a) => a.entry),
			["AF-006"],
		);
		const critical = evaluateReport(
			"pnpm-audit",
			auditReport(advisory("critical")),
			register(auditEntry),
			TODAY,
			{
				workspace: "services/custom-example",
			},
		);
		assert.equal(critical.failures.length, 1);
		assert.match(critical.failures[0].label, /services\/custom-example/);
	});

	it("does not gate a Trivy finding without a fix, and scopes entries to the image", () => {
		const noFix = evaluateReport(
			"trivy",
			trivyReport([trivyVuln({ FixedVersion: "" })]),
			register(),
			TODAY,
			{ image: "x" },
		);
		assert.deepEqual(noFix.failures, []);
		const otherImage = evaluateReport(
			"trivy",
			trivyReport([trivyVuln()]),
			register(trivyEntry),
			TODAY,
			{
				image: "giano-bundler",
			},
		);
		assert.equal(otherImage.failures.length, 1);
	});

	it("names the gitleaks rule, file and commit but never the secret", () => {
		const result = evaluateReport(
			"gitleaks",
			JSON.stringify([leak]),
			register(),
			TODAY,
		);
		assert.match(
			result.failures[0].label,
			/private-key in keys\.txt:3 \(commit 0123456789ab\)/,
		);
		assert.doesNotMatch(JSON.stringify(result), /SUPERSECRETVALUE/);
		assert.deepEqual(
			evaluateReport("gitleaks", "[]", register(), TODAY).failures,
			[],
		);
	});
});

describe("check-accepted-findings: CLI", () => {
	const root = mkdtempSync(join(tmpdir(), "accepted-findings-cli-"));
	after(() => rmSync(root, { recursive: true, force: true }));
	mkdirSync(join(root, "security"));
	writeFileSync(
		join(root, "security/accepted-findings.json"),
		JSON.stringify(register(entry())),
	);
	const quiet = (fn) => {
		const { log, error } = console;
		console.log = console.error = () => {};
		try {
			return fn();
		} finally {
			Object.assign(console, { log, error });
		}
	};

	it("fails closed when the report file does not exist", () => {
		assert.equal(
			quiet(() =>
				main(["--tool", "slither", "--report", join(root, "nope.json")], {
					root,
					today: TODAY,
				}),
			),
			1,
		);
	});

	it("needs --workspace for pnpm-audit and --image for trivy", () => {
		writeFileSync(join(root, "audit.json"), auditReport({}));
		assert.equal(
			quiet(() =>
				main(["--tool", "pnpm-audit", "--report", join(root, "audit.json")], {
					root,
					today: TODAY,
				}),
			),
			1,
		);
		assert.equal(
			quiet(() =>
				main(
					[
						"--tool",
						"pnpm-audit",
						"--workspace",
						".",
						"--report",
						join(root, "audit.json"),
					],
					{ root, today: TODAY },
				),
			),
			0,
		);
		assert.equal(
			quiet(() =>
				main(["--tool", "trivy", "--report", join(root, "audit.json")], {
					root,
					today: TODAY,
				}),
			),
			1,
		);
	});

	it("passes a matched report and fails an unmatched one", () => {
		writeFileSync(join(root, "slither.json"), slitherReport([slitherHigh]));
		assert.equal(
			quiet(() =>
				main(["--tool", "slither", "--report", join(root, "slither.json")], {
					root,
					today: TODAY,
				}),
			),
			0,
		);
		writeFileSync(
			join(root, "slither.json"),
			slitherReport([{ ...slitherHigh, id: "f".repeat(64) }]),
		);
		assert.equal(
			quiet(() =>
				main(["--tool", "slither", "--report", join(root, "slither.json")], {
					root,
					today: TODAY,
				}),
			),
			1,
		);
	});

	it("rejects an unknown flag", () => {
		assert.equal(
			quiet(() => main(["--fail-on", "low"], { root, today: TODAY })),
			1,
		);
	});
});
