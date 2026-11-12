import assert from "node:assert/strict";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";

import {
	checkAderynConfig,
	checkGitleaksConfig,
	checkPnpmAuditSettings,
	checkRepository,
	checkSlitherConfig,
	evaluateReport,
	findInSourceSuppressions,
	main,
	ReportError,
	SLITHER_SCOPE,
	usableEntries,
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
const DEFAULT_RULES = "[extend]\nuseDefault = true\n\n";
const ADERYN_TOML =
	'version = 1\nroot = "."\nsrc = "src"\nexclude = ["src/testing/"]\n';

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

	it("rejects an id that is not a string, even one that reads as a valid id", () => {
		for (const id of [["AF-002"], 2, { id: "AF-002" }]) {
			const reg = register(entry(), entry({ id }));
			assert.deepEqual(
				rules(validateRegister(reg, TODAY)),
				["bad-id"],
				`${JSON.stringify(id)}`,
			);
			assert.deepEqual(
				usableEntries(reg, TODAY).map((e) => e.id),
				["AF-001"],
			);
		}
	});

	it("rejects an entry accepted after today, so it cannot take effect early", () => {
		const future = entry({ accepted: "2099-01-01", expires: "2099-06-30" });
		const errs = validateRegister(register(future), TODAY);
		assert.deepEqual(rules(errs), ["accepted-in-future"]);
		assert.match(errs[0].message, /2099-01-01/);
		assert.deepEqual(
			validateRegister(register(future), "2099-01-01"),
			[],
			"passes from its accepted date",
		);
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
		for (const owner of [
			"Security Team",
			"Sarah Thompson; John Smith",
			"Sarah + John",
			"Sarah | John",
			"Sarah or John",
			"Sarah\nJohn",
			"Platform Teams",
			"Security Group",
		])
			assert.deepEqual(
				rules(validateRegister(register(entry({ owner })), TODAY)),
				["bad-owner"],
				owner,
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
		const toml = `${DEFAULT_RULES}[[allowlists]]\ndescription = "AF-009: Anvil keys"\n`;
		assert.match(
			checkGitleaksConfig(toml, new Set(["AF-008"]))[0].message,
			/\(AF-009 is not one\)/,
		);
	});

	it("passes a gitleaks allowlist that names an entry, and rejects disabledRules", () => {
		const ok = `${DEFAULT_RULES}[[allowlists]]\ndescription = "AF-008: public Anvil development keys"\n`;
		assert.deepEqual(checkGitleaksConfig(ok, new Set(["AF-008"])), []);
		const disabled =
			'[extend]\nuseDefault = true\ndisabledRules = ["generic-api-key"]\n';
		assert.deepEqual(rules(checkGitleaksConfig(disabled, new Set())), [
			"config-suppression",
		]);
	});

	it("allows exactly the fixed scope in slither.config.json", () => {
		const scope = { "//": ["reason"], ...SLITHER_SCOPE };
		assert.deepEqual(checkSlitherConfig(JSON.stringify(scope)), []);
		assert.deepEqual(checkSlitherConfig(JSON.stringify(SLITHER_SCOPE)), []);
		for (const config of [
			{ ...scope, detectors_to_exclude: "arbitrary-send-eth" },
			{ ...scope, exclude_high: true },
			{ ...scope, exclude_dependencies: true },
			{ ...scope, filter_paths: "packages/contracts/src/" },
			{ ...scope, include_paths: "packages/contracts/src/,.*" },
			{ ...scope, show_ignored_findings: false },
			{ ...scope, exclude_optimization: 1 },
			{ ...scope, exclude_optimization: undefined },
		])
			assert.deepEqual(
				rules(checkSlitherConfig(JSON.stringify(config))),
				["config-scope"],
				JSON.stringify(config),
			);
		assert.match(
			checkSlitherConfig(JSON.stringify({ ...scope, exclude_high: true }))[0]
				.message,
			/differs from the fixed scope in: exclude_high\./,
		);
	});

	it("reads slither.config.json key forms as Slither does", () => {
		const body = JSON.stringify(SLITHER_SCOPE).slice(1, -1);
		for (const text of [
			// An escaped key name is still that key.
			`{${body},"exclude\\u005fhigh":true}`,
			// The last of two duplicate keys wins, in JSON.parse and in Python's json.
			`{${body},"show_ignored_findings":false}`,
			`{"__proto__":{"exclude_high":true},${body}}`,
		])
			assert.deepEqual(rules(checkSlitherConfig(text)), ["config-scope"], text);
		for (const text of ["{", "[]", "NaN", `{${body},"x":NaN}`])
			assert.deepEqual(
				rules(checkSlitherConfig(text)),
				["invalid-config"],
				text,
			);
	});

	it("allows exactly the fixed lines in aderyn.toml, apart from blank lines and comments", () => {
		const scope = `# reason\n\n  # indented reason\n${ADERYN_TOML}\n# end\n`;
		assert.deepEqual(checkAderynConfig(scope), []);
		assert.deepEqual(
			checkAderynConfig(ADERYN_TOML.replaceAll("\n", "\r\n")),
			[],
		);
		const errs = checkAderynConfig(
			`${scope}[detectors]\nexclude = ["yul-return"]\n`,
		);
		assert.deepEqual(
			errs.map((e) => [e.line, e.rule]),
			[[10, "config-scope"]],
		);
		assert.match(
			errs[0].message,
			/^has '\[detectors\]' where it must have nothing more\./,
		);
		const missing = checkAderynConfig(ADERYN_TOML.replace('src = "src"\n', ""));
		assert.deepEqual(
			missing.map((e) => e.line),
			[3],
		);
		assert.match(
			missing[0].message,
			/^has 'exclude = \["src\/testing\/"\]' where it must have 'src = "src"'\./,
		);
		assert.match(
			checkAderynConfig("version = 1\n")[0].message,
			/^ends where it must have 'root = "\."'\./,
		);
	});

	it("rejects any other line in aderyn.toml, whatever TOML form it takes", () => {
		for (const toml of [
			ADERYN_TOML.replace('src = "src"', 'src = "src/testing"'),
			ADERYN_TOML.replace('"src/testing/"', '"src/"'),
			ADERYN_TOML.replace('root = "."', 'root = "lib"'),
			ADERYN_TOML.replace('src = "src"\n', ""),
			`${ADERYN_TOML}include = ["src/utils/"]\n`,
			// The same values in another form, or with a trailing comment, are not the fixed lines.
			ADERYN_TOML.replace('root = "."', 'root = "." # comment'),
			ADERYN_TOML.replace('["src/testing/"]', '[ "src/testing/" ]'),
			ADERYN_TOML.replace('src = "src"', "src = 'src'"),
			ADERYN_TOML.replace(
				'exclude = ["src/testing/"]',
				'exclude = [\n"src/testing/",\n]',
			),
			// Every form that sets detectors.
			`${ADERYN_TOML}[detectors]\n`,
			`${ADERYN_TOML}["detectors"]\n`,
			`${ADERYN_TOML}detectors.yul-return = false\n`,
			`${ADERYN_TOML}detectors = { yul-return = false }\n`,
			`${ADERYN_TOML}"src" = "src"\n`,
			`${ADERYN_TOML}x = '''\n# not a comment\n'''\n`,
			`﻿${ADERYN_TOML}`,
			"",
		])
			assert.deepEqual(rules(checkAderynConfig(toml)), ["config-scope"], toml);
	});

	it("lets each gitleaks entry accept exactly one allowlist, named first in its description", () => {
		const ids = new Set(["AF-008", "AF-009"]);
		const block = (d) => `[[allowlists]]\ndescription = "${d}"\n`;
		assert.deepEqual(
			checkGitleaksConfig(
				`${DEFAULT_RULES}${block("AF-008: Anvil keys")}${block("AF-009: fixtures")}`,
				ids,
			),
			[],
		);
		for (const toml of [
			`${DEFAULT_RULES}${block("AF-008: Anvil keys")}[[allowlists]]\ndescription = "AF-008: all"\nregexes = ['''.*''']\n`,
			`${DEFAULT_RULES}${block("unrelated; NOT AF-008")}`,
			`${DEFAULT_RULES}${block("AF-008 and AF-009")}`,
			`${DEFAULT_RULES}${block("AF-0081 other")}`,
		])
			assert.deepEqual(
				rules(checkGitleaksConfig(toml, ids)),
				["suppression-without-entry"],
				toml,
			);
	});

	it("rejects pnpm settings that hide advisories from pnpm audit", () => {
		for (const text of [
			"auditConfig:\n  ignoreGhsas:\n    - GHSA-x\n",
			"ignore:\n  - GHSA-x\n",
			"audit-level=critical\n",
			"ignore=GHSA-x\n",
			'{ "pnpm": { "auditConfig": { "ignoreCves": ["CVE-1"] } } }',
		])
			assert.equal(
				rules(checkPnpmAuditSettings([{ file: "f", text }]))[0],
				"suppression-setting",
				text,
			);
		for (const [file, text] of [
			[
				"package.json",
				'{ "pnpm": { "\\u0061uditConfig": { "ignoreGhsas": ["G"] } } }',
			],
			["pnpm-workspace.yaml", '"\\x61uditConfig":\n  ignoreGhsas: [G]\n'],
		])
			assert.equal(
				rules(checkPnpmAuditSettings([{ file, text }]))[0],
				"suppression-setting",
				text,
			);
		assert.deepEqual(
			checkPnpmAuditSettings([
				{
					file: "pnpm-workspace.yaml",
					text: "packages:\n  - services/*\nignoredBuiltDependencies:\n  - esbuild\nminimumReleaseAge: 10080\n",
				},
			]),
			[],
		);
	});

	it("lets an allowlist hold only a description and regexes", () => {
		const ids = new Set(["AF-008"]);
		const head = `${DEFAULT_RULES}[[allowlists]]\ndescription = "AF-008: Anvil keys"\nregexes = ['(?i)^(0x)?ac09$']\n`;
		assert.deepEqual(checkGitleaksConfig(head, ids), []);
		for (const extra of [
			"paths = ['''.*''']",
			'commits = ["abc123"]',
			'stopwords = ["token"]',
			'regexTarget = "line"',
			'condition = "AND"',
			'regexes.x = "y"',
		]) {
			const errs = checkGitleaksConfig(`${head}${extra}\n`, ids);
			assert.deepEqual(rules(errs), ["config-suppression"], extra);
			assert.equal(errs[0].line, 7, extra);
		}
	});

	it("requires .gitleaks.toml to keep the default rules and rejects custom rules", () => {
		const ids = new Set(["AF-008"]);
		const allowlist = '[[allowlists]]\ndescription = "AF-008"\n';
		for (const [toml, expected] of [
			[allowlist, ["missing-default-rules"]],
			["", ["missing-default-rules"]],
			[
				`[extend]\nuseDefault = false\n${allowlist}`,
				["config-suppression", "missing-default-rules"],
			],
			[
				`[extend]\npath = "weak.toml"\n${allowlist}`,
				["config-suppression", "missing-default-rules"],
			],
			[
				`[extend]\nurl = "https://example.com/weak.toml"\n${allowlist}`,
				["config-suppression", "missing-default-rules"],
			],
			[
				`${DEFAULT_RULES}[[rules]]\nid = "generic-api-key"\nregex = '''zzz'''\n`,
				["config-suppression"],
			],
			[
				`${DEFAULT_RULES}[[rules]]\nid = "custom"\nregex = 'x'\n[[rules.allowlists]]\npaths = ["x"]\n`,
				["config-suppression", "unsupported-config"],
			],
			[`useDefault = true\n${DEFAULT_RULES}`, ["config-suppression"]],
		])
			assert.deepEqual(
				rules(checkGitleaksConfig(toml, ids)).sort(),
				expected.sort(),
				toml,
			);
	});

	it("allows a custom gitleaks rule only with a giano- id, so it cannot replace a default rule", () => {
		const ids = new Set();
		const rule = (id, extra = "") =>
			`[[rules]]\n${id === null ? "" : `id = "${id}"\n`}description = "Infura key"\nregex = '(?i)infura\\.io/v3/([0-9a-f]{32})'\nkeywords = ["infura.io"]\n${extra}`;
		assert.deepEqual(
			checkGitleaksConfig(
				`${DEFAULT_RULES}${rule("giano-infura-key")}${rule("giano-alchemy-key")}`,
				ids,
			),
			[],
		);
		for (const id of [
			"generic-api-key",
			"giano-",
			"giano",
			"Giano-x",
			"x-giano-key",
			null,
		]) {
			const errs = checkGitleaksConfig(`${DEFAULT_RULES}${rule(id)}`, ids);
			assert.deepEqual(rules(errs), ["config-suppression"], String(id));
			assert.equal(errs[0].line, 4, String(id));
			assert.match(errs[0].message, /starts with giano-/, String(id));
		}
		const twice = checkGitleaksConfig(
			`${DEFAULT_RULES}${rule("giano-x")}${rule("giano-x")}`,
			ids,
		);
		assert.deepEqual(rules(twice), ["config-suppression"]);
		assert.match(
			twice[0].message,
			/reuses id 'giano-x' from the rule on line 4/,
		);
		assert.deepEqual(
			rules(
				checkGitleaksConfig(
					`${DEFAULT_RULES}[[rules]]\nid = "giano-x"\ndescription = "no regex"\n`,
					ids,
				),
			),
			["unsupported-config"],
		);
	});

	it("lets a custom gitleaks rule hold only an id, a description, a regex and keywords", () => {
		const head = `${DEFAULT_RULES}[[rules]]\nid = "giano-x"\nregex = 'x'\n`;
		for (const extra of [
			"path = '''.*\\.md'''",
			"entropy = 4.5",
			"secretGroup = 2",
			'tags = ["x"]',
			"regexTarget = 'line'",
			'keywords.x = "y"',
		]) {
			const errs = checkGitleaksConfig(`${head}${extra}\n`, new Set());
			assert.deepEqual(rules(errs), ["config-suppression"], extra);
			assert.equal(errs[0].line, 7, extra);
		}
	});

	it("detects RPC provider keys with the rules in .gitleaks.toml, and captures only the key", () => {
		const toml = readFileSync(
			new URL("../.gitleaks.toml", import.meta.url),
			"utf8",
		);
		// RE2 writes case-insensitivity as a (?i) prefix, JavaScript as the i flag.
		const regexes = new Map(
			[
				...toml.matchAll(
					/^id = "(giano-[a-z-]+)"\nd[^\n]*\nregex = '\(\?i\)([^']+)'$/gm,
				),
			].map((m) => [m[1], new RegExp(m[2], "i")]),
		);
		assert.deepEqual(
			[...regexes.keys()],
			[
				"giano-infura-key",
				"giano-alchemy-key",
				"giano-quicknode-key",
				"giano-ankr-key",
			],
		);
		const hex = (n) => "0123456789abcdef".repeat(4).slice(0, n);
		const alchemy = "AbCdEfGhIjKlMnOpQrStUvWxYz012_-9";
		for (const [text, id, key] of [
			[
				`RPC=https://base-sepolia.infura.io/v3/${hex(32)}`,
				"giano-infura-key",
				hex(32),
			],
			[
				`"wss://mainnet.infura.io/ws/v3/${hex(32)}"`,
				"giano-infura-key",
				hex(32),
			],
			[
				`url: "https://eth-mainnet.g.alchemy.com/v2/${alchemy}"`,
				"giano-alchemy-key",
				alchemy,
			],
			[
				`wss://base-mainnet.g.alchemy.com/v2/${alchemy}`,
				"giano-alchemy-key",
				alchemy,
			],
			[
				`https://eth-mainnet.g.alchemy.com/nft/v3/${alchemy}/getNFTsForOwner`,
				"giano-alchemy-key",
				alchemy,
			],
			[
				`https://api.g.alchemy.com/prices/v1/${alchemy}/tokens/by-symbol`,
				"giano-alchemy-key",
				alchemy,
			],
			[
				`https://eth-mainnet.alchemyapi.io/v2/${alchemy}`,
				"giano-alchemy-key",
				alchemy,
			],
			[
				`https://x.base-mainnet.quiknode.pro/${hex(40)}/`,
				"giano-quicknode-key",
				hex(40),
			],
			[`'https://rpc.ankr.com/base/${hex(64)}'`, "giano-ankr-key", hex(64)],
			[`wss://rpc.ankr.com/eth/ws/${hex(64)}`, "giano-ankr-key", hex(64)],
		]) {
			const found = [...regexes].filter(([, r]) => r.test(text));
			assert.deepEqual(
				found.map(([i]) => i),
				[id],
				text,
			);
			assert.equal(found[0][1].exec(text)[1], key, text);
		}
		for (const text of [
			"BASE_RPC_URL=https://base-mainnet.infura.io/v3/<infura-token>",
			"RPC_ORIGIN=https://base-sepolia.g.alchemy.com",
			"https://eth-mainnet.g.alchemy.com/v2/docs-demo",
			"https://eth-mainnet.g.alchemy.com/nft/v3/docs-demo/getNFTsForOwner",
			`https://eth-mainnet.g.alchemy.com/v2/\${ALCHEMY_KEY}`,
			"https://rpc.ankr.com/base",
			"wss://rpc.ankr.com/eth/ws",
		])
			for (const [id, r] of regexes)
				assert.equal(r.test(text), false, `${id}: ${text}`);
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
			[
				"[allowlist]\npaths = ''''\ndescription = \"AF-008\"\n''''\n",
				"unsupported-config",
			],
		])
			assert.ok(rules(checkGitleaksConfig(toml, ids)).includes(rule), toml);
		const ok =
			"title = \"Giano\"\n[extend]\nuseDefault = true\n\n[ allowlist ]\ndescription = \"AF-008\" # c\nregexes = ['''0x[a-f]{64}''']\n";
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
			JSON.stringify(SLITHER_SCOPE),
		);
		write("packages/contracts/aderyn.toml", ADERYN_TOML);
		assert.deepEqual(checkRepository(root, TODAY), []);

		write(
			"packages/contracts/src/sub/B.sol",
			"contract B {\n// slither-disable-next-line x\n}\n",
		);
		write("packages/contracts/slither.db.json", "[]");
		write(
			".gitleaks.toml",
			`${DEFAULT_RULES}[[allowlists]]\ndescription = "no entry"\n`,
		);
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

	it("rejects a symlink under packages/contracts/src and pnpm audit settings in a workspace", () => {
		const dir = mkdtempSync(join(tmpdir(), "accepted-findings-links-"));
		try {
			mkdirSync(join(dir, "security"));
			writeFileSync(
				join(dir, "security/accepted-findings.json"),
				JSON.stringify(register(entry())),
			);
			mkdirSync(join(dir, "hidden"));
			writeFileSync(join(dir, "hidden/Baz.sol"), "// slither-disable-start\n");
			mkdirSync(join(dir, "packages/contracts/src"), { recursive: true });
			writeFileSync(
				join(dir, "packages/contracts/slither.config.json"),
				JSON.stringify(SLITHER_SCOPE),
			);
			writeFileSync(join(dir, "packages/contracts/aderyn.toml"), ADERYN_TOML);
			symlinkSync(
				join(dir, "hidden/Baz.sol"),
				join(dir, "packages/contracts/src/Baz.sol"),
			);
			mkdirSync(join(dir, "services/custom-example"), { recursive: true });
			writeFileSync(
				join(dir, "services/custom-example/.npmrc"),
				"audit-level=critical\n",
			);
			const errs = checkRepository(dir, TODAY);
			assert.deepEqual(rules(errs).sort(), ["suppression-setting", "symlink"]);
			assert.ok(errs.some((e) => e.file === "packages/contracts/src/Baz.sol"));
			assert.ok(errs.some((e) => e.file === "services/custom-example/.npmrc"));
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("fails when src is a symlink, a tool config is missing, or slither.conf.json exists", () => {
		const dir = mkdtempSync(join(tmpdir(), "accepted-findings-src-"));
		try {
			mkdirSync(join(dir, "security"));
			writeFileSync(
				join(dir, "security/accepted-findings.json"),
				JSON.stringify(register(entry())),
			);
			mkdirSync(join(dir, "production"));
			mkdirSync(join(dir, "packages/contracts"), { recursive: true });
			symlinkSync(join(dir, "production"), join(dir, "packages/contracts/src"));
			writeFileSync(
				join(dir, "packages/contracts/slither.conf.json"),
				'{ "exclude_high": true }',
			);
			const errs = checkRepository(dir, TODAY);
			assert.deepEqual(errs.map((e) => `${e.file} ${e.rule}`).sort(), [
				"packages/contracts/aderyn.toml config-scope",
				"packages/contracts/slither.conf.json suppression-file",
				"packages/contracts/slither.config.json config-scope",
				"packages/contracts/src symlink",
			]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
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
				`${DEFAULT_RULES}[[allowlists]]\ndescription = "AF-008: public Anvil keys"\n`,
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
// Like Aderyn 0.6.8: issue_count counts issues (detectors), not instances.
const aderynReport = (high, low = []) =>
	JSON.stringify({
		issue_count: { high: high.length, low: low.length },
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
// Like pnpm audit: metadata.vulnerabilities counts each advisory once, by severity.
const auditReport = (advisories) => {
	const vulnerabilities = {
		info: 0,
		low: 0,
		moderate: 0,
		high: 0,
		critical: 0,
	};
	for (const a of Object.values(advisories))
		if (a?.severity in vulnerabilities) vulnerabilities[a.severity]++;
	return JSON.stringify({ advisories, metadata: { vulnerabilities } });
};
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

		it("fails a finding whose only matching entry is accepted after today", () => {
			const result = run(
				c.report,
				register({ ...c.entry, accepted: "2026-11-10" }),
			);
			assert.equal(result.failures.length, 1);
			assert.match(result.failures[0].message, /not valid/);
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

	it("fails a report with a missing or unknown severity, and keeps Trivy UNKNOWN below the gate", () => {
		const bad = [
			["slither", slitherReport([{ ...slitherHigh, impact: undefined }])],
			["slither", slitherReport([{ ...slitherHigh, impact: "high" }])],
			["pnpm-audit", auditReport(advisory(undefined)), { workspace: "." }],
			["pnpm-audit", auditReport(advisory("HIGH")), { workspace: "." }],
			[
				"trivy",
				trivyReport([trivyVuln({ Severity: undefined })]),
				{ image: "giano-wallet-api" },
			],
			[
				"trivy",
				trivyReport([trivyVuln({ Severity: "high" })]),
				{ image: "giano-wallet-api" },
			],
		];
		for (const [tool, text, options] of bad)
			assert.throws(
				() => evaluateReport(tool, text, register(), TODAY, options),
				/severity/,
				`${tool} ${text}`,
			);
		assert.deepEqual(
			evaluateReport(
				"trivy",
				trivyReport([trivyVuln({ Severity: "UNKNOWN" })]),
				register(),
				TODAY,
				{ image: "giano-wallet-api" },
			),
			{ accepted: [], failures: [], belowGate: 1 },
		);
	});

	it("accepts a gating finding only up to the severity its entry was assessed at", () => {
		const audit = (severity, entrySeverity) =>
			evaluateReport(
				"pnpm-audit",
				auditReport(advisory(severity)),
				register({ ...auditEntry, severity: entrySeverity }),
				TODAY,
				{ workspace: "." },
			);
		const raised = audit("high", "moderate");
		assert.deepEqual(raised.accepted, []);
		assert.match(
			raised.failures[0].message,
			/matches AF-006, but the entry accepts moderate and the tool now reports high/,
		);
		assert.equal(audit("critical", "high").failures.length, 1);
		assert.deepEqual(
			audit("high", "critical").accepted.map((a) => a.entry),
			["AF-006"],
		);
		assert.deepEqual(
			audit("moderate", "moderate").accepted.map((a) => a.entry),
			["AF-006"],
		);
		const slither = evaluateReport(
			"slither",
			slitherReport([slitherHigh]),
			register(entry({ severity: "medium" })),
			TODAY,
		);
		assert.match(slither.failures[0].message, /accepts medium .* reports high/);
	});

	it("fails an Aderyn issue that lists no instances", () => {
		for (const level of ["high", "low"]) {
			const issue = { detector_name: "x", instances: [] };
			const text =
				level === "high" ? aderynReport([issue]) : aderynReport([], [issue]);
			assert.throws(
				() => evaluateReport("aderyn", text, [], TODAY),
				/Aderyn issue x lists no instances/,
				level,
			);
		}
	});

	it("fails a report whose findings are not objects or whose lists are null", () => {
		const cases = [
			[
				"slither",
				JSON.stringify({ success: true, results: { detectors: [null] } }),
			],
			[
				"slither",
				JSON.stringify({ success: true, results: { detectors: null } }),
			],
			["aderyn", aderynReport([{ detector_name: "x", instances: [null] }])],
			["aderyn", aderynReport([null])],
			[
				"pnpm-audit",
				JSON.stringify({
					advisories: { 1: null },
					metadata: { vulnerabilities: {} },
				}),
				{ workspace: "." },
			],
			[
				"trivy",
				JSON.stringify({ SchemaVersion: 2, Results: [null] }),
				{ image: "i" },
			],
			[
				"trivy",
				JSON.stringify({ SchemaVersion: 2, Results: null }),
				{ image: "i" },
			],
			[
				"trivy",
				JSON.stringify({
					SchemaVersion: 2,
					Results: [{ Vulnerabilities: null }],
				}),
				{ image: "i" },
			],
			["gitleaks", "[null]"],
		];
		for (const [tool, text, options] of cases)
			assert.throws(
				() => evaluateReport(tool, text, register(), TODAY, options),
				ReportError,
				`${tool} ${text}`,
			);
	});

	it("fails an Aderyn report whose counts or categories do not match its issues", () => {
		const run = (report) => () =>
			evaluateReport("aderyn", JSON.stringify(report), register(), TODAY);
		const base = JSON.parse(aderynReport([aderynHigh]));
		assert.throws(
			run({
				...base,
				issue_count: { high: 3, low: 0 },
				high_issues: { issues: [] },
			}),
			/counts 3 high issues but lists 0/,
		);
		assert.throws(run({ ...base, issue_count: undefined }), /counts undefined/);
		assert.throws(
			run({ ...base, critical_issues: { issues: [] } }),
			/unknown categories/,
		);
	});

	it("fails a pnpm audit report whose summary counts a gated advisory it does not list", () => {
		const report = JSON.stringify({
			advisories: {},
			metadata: { vulnerabilities: { moderate: 0, high: 1, critical: 0 } },
		});
		assert.throws(
			() =>
				evaluateReport("pnpm-audit", report, register(), TODAY, {
					workspace: ".",
				}),
			/counts 1 high advisories but lists 0/,
		);
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
		const failures = evaluateReport(
			"aderyn",
			aderynReport([moved]),
			register(aderynEntry),
			TODAY,
		).failures;
		assert.equal(failures.length, 2);
		assert.match(failures[0].message, /no entry in/);
		assert.match(failures[1].label, /^AF-005 in /);
	});

	it("fails a Slither or Aderyn entry that matches no finding in the report", () => {
		const slither = evaluateReport(
			"slither",
			slitherReport([]),
			register(entry()),
			TODAY,
		);
		assert.deepEqual(slither.failures, [
			{
				label: "AF-001 in security/accepted-findings.json",
				message:
					"matches no slither finding in this report. Remove the entry if the finding is fixed, or update its match if the finding moved",
			},
		]);
		const aderyn = evaluateReport(
			"aderyn",
			aderynReport([]),
			register(aderynEntry, entry()),
			TODAY,
		);
		assert.deepEqual(
			aderyn.failures.map((f) => f.label),
			["AF-005 in security/accepted-findings.json"],
		);
		// A finding that the entry matches but no longer covers still uses the entry.
		const raised = evaluateReport(
			"slither",
			slitherReport([slitherHigh]),
			register(entry({ severity: "medium" })),
			TODAY,
		);
		assert.equal(raised.failures.length, 1);
		assert.match(raised.failures[0].message, /accepts medium/);
		// An expired entry that still matches its finding fails once, for the expiry.
		const expired = evaluateReport(
			"slither",
			slitherReport([slitherHigh]),
			register(entry({ accepted: "2026-01-01", expires: "2026-06-30" })),
			TODAY,
		);
		assert.equal(expired.failures.length, 1);
		assert.match(expired.failures[0].message, /matches AF-001, but the entry/);
	});

	it("does not fail an unused entry of a tool whose findings change without a code change", () => {
		for (const [tool, text, options, e] of [
			["pnpm-audit", auditReport({}), { workspace: "." }, auditEntry],
			["trivy", trivyReport([]), { image: "giano-wallet-api" }, null],
			["gitleaks", "[]", {}, null],
		])
			assert.deepEqual(
				evaluateReport(tool, text, register(...(e ? [e] : [])), TODAY, options)
					.failures,
				[],
				tool,
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

	it("fails closed when the report file does not exist or is a directory", () => {
		mkdirSync(join(root, "a-directory"), { recursive: true });
		for (const report of [join(root, "nope.json"), join(root, "a-directory")])
			assert.equal(
				quiet(() =>
					main(["--tool", "slither", "--report", report], {
						root,
						today: TODAY,
					}),
				),
				1,
				report,
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
