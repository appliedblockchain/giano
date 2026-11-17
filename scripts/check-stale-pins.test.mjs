import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	actionPins,
	coerceVersion,
	deferralFor,
	newestQualifying,
	npmPins,
	npmReleases,
	parseDeferrals,
	renderReport,
	staleRows,
	TOOLS,
	toolPins,
	unversionedActionPins,
	updateType,
} from "./check-stale-pins.mjs";

const NOW = Date.parse("2026-11-17T12:00:00Z");
const DAY = 24 * 60 * 60 * 1000;
const ago = (days) => new Date(NOW - days * DAY).toISOString();

/** A fetchJson that answers from a URL map and fails on anything else. */
const fakeFetch = (responses) => async (url) => {
	if (!(url in responses)) throw new Error(`${url}: HTTP 404`);
	const value = responses[url];
	if (value instanceof Error) throw value;
	return value;
};
const npmDoc = (times, versions = {}) => ({
	time: { created: ago(999), modified: ago(0), ...times },
	versions: {
		...Object.fromEntries(Object.keys(times).map((v) => [v, {}])),
		...versions,
	},
});
const NPM = (name) =>
	`https://registry.npmjs.org/${name.replaceAll("/", "%2F")}`;
const GH = (repo) =>
	`https://api.github.com/repos/${repo}/releases?per_page=100`;

const DEFERRALS_HEADER =
	"| Name | Held version | Reason | Owner | Review-by |\n|---|---|---|---|---|\n";

describe("versions", () => {
	it("classifies the size of an update", () => {
		assert.equal(updateType("1.2.3", "2.0.0"), "major");
		assert.equal(updateType("1.2.3", "1.3.0"), "minor");
		assert.equal(updateType("1.2.3", "1.2.4"), "patch");
	});

	it("pads an .nvmrc version", () => {
		assert.equal(coerceVersion("v24.22"), "24.22.0");
		assert.equal(coerceVersion("24"), "24.0.0");
		assert.equal(coerceVersion("latest"), null);
	});

	it("takes the newest stable release older than the cutoff", () => {
		const releases = [
			{ version: "1.0.0", date: ago(30) },
			{ version: "1.1.0", date: ago(10) },
			{ version: "1.2.0", date: ago(3) }, // younger than 7 days
			{ version: "2.0.0-rc.1", date: ago(20) }, // pre-release
		];
		assert.equal(newestQualifying(releases, NOW - 7 * DAY).version, "1.1.0");
		assert.equal(newestQualifying(releases, NOW - 7 * DAY, 2), undefined);
	});
});

describe("npmPins", () => {
	it("returns exact pins and aliases, and skips workspace:, catalog: and git pins", () => {
		const pins = npmPins(
			[
				{
					file: "services/a/package.json",
					manifest: {
						dependencies: {
							viem: "2.1.0",
							"@x/lib": "workspace:*",
							shared: "catalog:",
							old: "npm:new-name@3.0.0",
						},
						devDependencies: {
							forked: "github:o/r#0123456789012345678901234567890123456789",
						},
						peerDependencies: { react: "^19" },
					},
				},
			],
			new Set(["@x/lib"]),
		);
		assert.deepEqual(
			pins.map((p) => [p.name, p.pinned]),
			[
				["viem", "2.1.0"],
				["new-name", "3.0.0"],
			],
		);
	});

	it("flags a pin on one of our own packages", () => {
		const [pin] = npmPins(
			[
				{
					file: "f",
					manifest: { dependencies: { "@appliedblockchain/x": "1.0.0" } },
				},
			],
			new Set(["@appliedblockchain/x"]),
		);
		assert.equal(pin.own, true);
	});
});

describe("actionPins", () => {
	it("reads the release comment of a SHA-pinned action, with or without a path", () => {
		const yml = [
			"    steps:",
			"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
			"      - uses: github/codeql-action/init@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1",
			"      - uses: ./.github/actions/local",
			"      - uses: docker://alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		].join("\n");
		assert.deepEqual(actionPins(yml, "w.yml"), [
			{ name: "actions/checkout", pinned: "7.0.1", where: "w.yml:2" },
			{ name: "github/codeql-action", pinned: "4.39.1", where: "w.yml:3" },
		]);
	});
});

describe("unversionedActionPins", () => {
	it("reports a SHA-pinned action without a release comment", () => {
		const yml = [
			"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
			"      - uses: foo/bar@3d3c42e5aac5ba805825da76410c181273ba90b1",
			"      - uses: foo/baz/sub@3d3c42e5aac5ba805825da76410c181273ba90b1 # release 1.2",
			"      - uses: actions/setup-node@v6",
		].join("\n");
		const problems = unversionedActionPins(yml, "w.yml");
		assert.equal(problems.length, 2);
		assert.match(problems[0], /^w\.yml:2: `foo\/bar`/);
		assert.match(problems[1], /^w\.yml:3: `foo\/baz`/);
	});
});

describe("toolPins", () => {
	const tool = (name, file) =>
		TOOLS.find((t) => t.name === name && t.files.includes(file));

	it("reads Node from .nvmrc", () => {
		assert.deepEqual(toolPins(tool("node", ".nvmrc"), "v24.22\n", ".nvmrc"), [
			{ name: "node", pinned: "24.22.0", where: ".nvmrc:1" },
		]);
	});

	it("reads the Foundry version below foundry-toolchain, past comment lines", () => {
		const yml = [
			"      - uses: foundry-rs/foundry-toolchain@dba66c27052e63476d886f22216e119ba7e615bf # v1.9.2",
			"        with:",
			"          # Pinned to the same Foundry release the repo pins everywhere else (the anvil",
			'          # image, e2e/devnet/with-pinned-anvil.mjs). "stable" drifting past it once moved',
			"          # the bytecode.",
			"          version: v1.7.1",
			"      - uses: foundry-rs/foundry-toolchain@dba66c27052e63476d886f22216e119ba7e615bf # v1.9.2",
			"        with:",
			"          version: v1.7.1",
		].join("\n");
		const workflowTool = tool("foundry", ".github/workflows/*.yml");
		assert.deepEqual(
			toolPins(workflowTool, yml, "ci.yml").map((p) => [p.pinned, p.where]),
			[
				["1.7.1", "ci.yml:6"],
				["1.7.1", "ci.yml:9"],
			],
		);
	});

	it("reads the Anvil pin of both devnet scripts", () => {
		const tool = TOOLS.find((t) =>
			t.files.includes("e2e/devnet/upgrade-paymaster.mjs"),
		);
		assert.deepEqual(
			toolPins(tool, 'const PINNED_ANVIL_VERSION = "1.7.1";', "u.mjs"),
			[{ name: "foundry", pinned: "1.7.1", where: "u.mjs:1" }],
		);
	});

	it("reads the pnpm version of packageManager", () => {
		const json = '{\n\t"packageManager": "pnpm@12.17.0+sha256.abc"\n}';
		assert.equal(
			toolPins(tool("pnpm", "package.json"), json, "package.json")[0].pinned,
			"12.17.0",
		);
	});
});

describe("parseDeferrals", () => {
	it("reads valid rows and ignores other tables", () => {
		const text = `| A | B |\n|---|---|\n| x | y |\n\n${DEFERRALS_HEADER}| \`vite\` | 6.x | plugin needs 6 | Dev | 2027-01-01 |\n`;
		const { rows, errors } = parseDeferrals(text);
		assert.deepEqual(errors, []);
		assert.equal(rows.length, 1);
		assert.equal(rows[0].Name, "vite");
		assert.equal(rows[0]["Held version"], "6.x");
	});

	it("reports a row with a missing owner, a bad date or a range", () => {
		const text = `${DEFERRALS_HEADER}| a | 1.0.0 | r |  | 2027-01-01 |\n| b | 1.0.0 | r | o | soon |\n| c | ^1 | r | o | 2027-01-01 |\n`;
		const { rows, errors } = parseDeferrals(text, "d.md");
		assert.equal(rows.length, 0);
		assert.equal(errors.length, 3);
		assert.match(errors[0], /^d\.md:3: .*Owner/);
		assert.match(errors[1], /Review-by/);
		assert.match(errors[2], /Held version/);
	});

	it("matches a held major only for pins in that major", () => {
		const rows = [{ Name: "actions/upload-artifact", "Held version": "4.x" }];
		assert.ok(deferralFor(rows, "actions/upload-artifact", "4.6.2"));
		assert.equal(
			deferralFor(rows, "actions/upload-artifact", "7.0.2"),
			undefined,
		);
	});
});

describe("npmReleases", () => {
	it("skips versions that were unpublished or are deprecated", async () => {
		const doc = npmDoc(
			{ "1.0.0": ago(60), "1.1.0": ago(30), "1.2.0": ago(20) },
			{ "1.2.0": { deprecated: "broken release" } },
		);
		delete doc.versions["1.1.0"]; // unpublished: still in `time`
		const releases = await npmReleases(fakeFetch({ [NPM("a")]: doc }), "a");
		assert.deepEqual(
			releases.map((r) => r.version),
			["1.0.0"],
		);
	});
});

describe("staleRows", () => {
	const run = (
		pins,
		{ deferrals = [], responses = {}, ownVersions = new Map() } = {},
	) =>
		staleRows({
			pins,
			deferrals,
			ownVersions,
			fetchJson: fakeFetch(responses),
			now: NOW,
		});
	const npm = (name, pinned, where = "package.json") => ({
		kind: "npm",
		name,
		pinned,
		where,
	});

	it("reports a pin behind a release older than 7 days, and ignores a younger one", async () => {
		const rows = await run([npm("a", "1.0.0"), npm("b", "1.0.0")], {
			responses: {
				[NPM("a")]: npmDoc({ "1.0.0": ago(60), "1.1.0": ago(8) }),
				[NPM("b")]: npmDoc({ "1.0.0": ago(60), "1.1.0": ago(6) }),
			},
		});
		assert.deepEqual(
			rows.map((r) => [r.name, r.status, r.latest, r.update]),
			[
				["a", "stale", "1.1.0", "minor"],
				["b", "current", "1.0.0", undefined],
			],
		);
	});

	it("groups the places a version is pinned and fetches each package once", async () => {
		let calls = 0;
		const rows = await staleRows({
			pins: [
				npm("a", "1.0.0", "x/package.json"),
				npm("a", "1.0.0", "y/package.json"),
			],
			deferrals: [],
			ownVersions: new Map(),
			now: NOW,
			fetchJson: async () => {
				calls++;
				return npmDoc({ "1.0.0": ago(60) });
			},
		});
		assert.equal(rows.length, 1);
		assert.deepEqual(rows[0].where, ["x/package.json", "y/package.json"]);
		assert.equal(calls, 1);
	});

	it("holds a pin with a deferral until its review date", async () => {
		const responses = {
			[NPM("a")]: npmDoc({ "1.0.0": ago(60), "2.0.0": ago(30) }),
		};
		const deferral = (reviewBy) => [
			{ Name: "a", "Held version": "1.0.0", "Review-by": reviewBy },
		];
		const [held] = await run([npm("a", "1.0.0")], {
			responses,
			deferrals: deferral("2026-12-01"),
		});
		assert.equal(held.status, "deferred");
		const [expired] = await run([npm("a", "1.0.0")], {
			responses,
			deferrals: deferral("2026-11-01"),
		});
		assert.equal(expired.status, "stale");
		assert.match(expired.note, /expired on 2026-11-01/);
	});

	it("reports a pin that a held major covers but is behind within that major", async () => {
		const responses = {
			[NPM("a")]: npmDoc({
				"4.0.0": ago(90),
				"4.1.0": ago(30),
				"7.0.0": ago(20),
			}),
		};
		const deferrals = [
			{ Name: "a", "Held version": "4.x", "Review-by": "2027-01-01" },
		];
		const [behind] = await run([npm("a", "4.0.0")], { responses, deferrals });
		assert.equal(behind.status, "stale");
		assert.equal(behind.latest, "4.1.0");
		const [held] = await run([npm("a", "4.1.0")], { responses, deferrals });
		assert.equal(held.status, "deferred");
		assert.equal(held.latest, "7.0.0");
	});

	it("compares our own package with the workspace version, without the registry", async () => {
		const pin = { ...npm("@appliedblockchain/x", "6.0.0"), own: true };
		const [row] = await run([pin], {
			ownVersions: new Map([["@appliedblockchain/x", "7.0.1"]]),
		});
		assert.equal(row.status, "stale");
		assert.equal(row.latest, "7.0.1");
	});

	it("reports a failed fetch as an error, never as current", async () => {
		const [row] = await run([npm("a", "1.0.0")], {
			responses: { [NPM("a")]: new Error("HTTP 500") },
		});
		assert.equal(row.status, "error");
	});

	it("gives the commit of a newer action release", async () => {
		const rows = await run(
			[{ kind: "action", name: "o/r", pinned: "1.0.0", where: "w.yml:3" }],
			{
				responses: {
					[GH("o/r")]: [
						{
							tag_name: "v1.0.0",
							published_at: ago(90),
							draft: false,
							prerelease: false,
						},
						{
							tag_name: "v1.1.0",
							published_at: ago(10),
							draft: false,
							prerelease: false,
						},
						{
							tag_name: "v2.0.0",
							published_at: ago(10),
							draft: false,
							prerelease: true,
						},
					],
					"https://api.github.com/repos/o/r/commits/v1.1.0": {
						sha: "a".repeat(40),
					},
				},
			},
		);
		assert.equal(rows[0].latest, "1.1.0");
		assert.equal(rows[0].sha, "a".repeat(40));
	});
});

describe("renderReport", () => {
	it("lists stale pins, errors and deferrals, but not current ones", () => {
		const md = renderReport(
			[
				{
					kind: "npm",
					name: "a",
					pinned: "1.0.0",
					latest: "1.1.0",
					update: "minor",
					status: "stale",
					where: ["p.json"],
				},
				{
					kind: "npm",
					name: "b",
					pinned: "1.0.0",
					latest: "1.0.0",
					status: "current",
					where: ["p.json"],
				},
				{
					kind: "tool",
					name: "c",
					pinned: "1.0.0",
					latest: "?",
					status: "error",
					note: "HTTP 500",
					where: ["x"],
				},
				{
					kind: "action",
					name: "d/e",
					pinned: "4.0.0",
					latest: "7.0.0",
					status: "deferred",
					note: "deferred until 2027-01-01",
					where: ["w"],
				},
			],
			["d.md:3: deferral row is missing Owner"],
		);
		assert.match(
			md,
			/^4 pins checked: 1 stale, 1 deferred, 1 failed, 1 current\./,
		);
		assert.match(
			md,
			/\| npm \| `a` \| 1\.0\.0 \| 1\.1\.0 \| minor \| `p\.json` \|/,
		);
		assert.match(md, /- tool `c` 1\.0\.0: HTTP 500/);
		assert.match(md, /- d\.md:3: deferral row is missing Owner/);
		assert.match(
			md,
			/\| action \| `d\/e` \| 4\.0\.0 \| 7\.0\.0 \| deferred until 2027-01-01 \|/,
		);
		assert.doesNotMatch(md, /`b`/);
	});
});
