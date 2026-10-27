import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
	checkWorkspace,
	findStaleExclusions,
	findUnfrozenInstalls,
	parseReleaseAgeConfig,
} from "./check-release-age.mjs";

const rules = (errs) => errs.map((e) => e.rule);

const workspace = (age, excludes = []) =>
	[
		"packages:",
		'  - "packages/*"',
		"overrides:",
		'  "ws@>=8.0.0 <8.21.0": "8.21.0"',
		"# Supply-chain policy",
		`minimumReleaseAge: ${age}`,
		...(excludes.length
			? ["minimumReleaseAgeExclude:", ...excludes.map((e) => `  - ${e}`)]
			: []),
		"allowBuilds:",
		"  esbuild: false",
	].join("\n");

describe("check-release-age: workspace config", () => {
	it("passes seven days with no exclusions", () => {
		assert.deepEqual(
			rules(checkWorkspace(workspace(10080), "pnpm-workspace.yaml")),
			[],
		);
	});

	it("rejects the old one-day window", () => {
		const errs = checkWorkspace(workspace(1440), "pnpm-workspace.yaml");
		assert.deepEqual(
			errs.map((e) => [e.line, e.rule]),
			[[6, "release-age-floor"]],
		);
	});

	it("rejects the three-day floor too", () => {
		assert.deepEqual(rules(checkWorkspace(workspace(4320), "f")), [
			"release-age-floor",
		]);
	});

	it("rejects a missing setting", () => {
		assert.deepEqual(rules(checkWorkspace("packages:\n  - e2e\n", "f")), [
			"release-age-missing",
		]);
	});

	it("rejects a blanket exclusion by name", () => {
		const errs = checkWorkspace(workspace(10080, ["postcss"]), "f");
		assert.deepEqual(rules(errs), ["exclusion-not-versioned"]);
		assert.match(errs[0].message, /'postcss'/);
	});

	it("rejects a scope-wide exclusion", () => {
		assert.deepEqual(
			rules(checkWorkspace(workspace(10080, ["'@appliedblockchain/*'"]), "f")),
			["exclusion-not-versioned"],
		);
	});

	it("rejects a ranged exclusion", () => {
		assert.deepEqual(
			rules(checkWorkspace(workspace(10080, ["lodash@^4.17.22"]), "f")),
			["exclusion-not-versioned"],
		);
	});

	it("accepts exact-version exclusions, scoped or not, quoted or not", () => {
		assert.deepEqual(
			rules(
				checkWorkspace(
					workspace(10080, [
						"lodash@4.17.22",
						"'@scope/pkg@1.2.3-rc.1' # GHSA-…, remove 2026-12-01",
					]),
					"f",
				),
			),
			[],
		);
	});

	it("parses the exclusion list and stops at the next key", () => {
		const config = parseReleaseAgeConfig(
			workspace(10080, ["a@1.0.0", "b@2.0.0"]),
		);
		assert.equal(config.minimumReleaseAge, 10080);
		assert.deepEqual(
			config.excludes.map((e) => e.entry),
			["a@1.0.0", "b@2.0.0"],
		);
	});
});

describe("check-release-age: frozen installs", () => {
	it("accepts a frozen install", () => {
		assert.deepEqual(
			findUnfrozenInstalls(
				"      - run: pnpm install --frozen-lockfile\n",
				"ci.yml",
			),
			[],
		);
	});

	it("rejects an unfrozen install and names the line", () => {
		const errs = findUnfrozenInstalls(
			"steps:\n      - run: pnpm install\n",
			"ci.yml",
		);
		assert.deepEqual(
			errs.map((e) => [e.line, e.rule]),
			[[2, "unfrozen-install"]],
		);
	});

	it("rejects the short form", () => {
		assert.deepEqual(
			rules(findUnfrozenInstalls("RUN pnpm i --filter x\n", "Dockerfile")),
			["unfrozen-install"],
		);
	});

	it("checks each command of a chained line on its own", () => {
		assert.deepEqual(
			rules(
				findUnfrozenInstalls(
					"RUN pnpm install --frozen-lockfile && pnpm install\n",
					"Dockerfile",
				),
			),
			["unfrozen-install"],
		);
	});

	it("ignores comments", () => {
		assert.deepEqual(
			findUnfrozenInstalls(
				"# `pnpm install` under emulation deadlocked\n",
				"docker.yml",
			),
			[],
		);
	});
});

describe("check-release-age: --registry", () => {
	const now = Date.parse("2026-11-10T00:00:00Z");
	const fetchJson = async (name) =>
		({
			lodash: {
				time: {
					"4.17.22": "2026-11-08T00:00:00Z",
					"4.17.21": "2021-02-20T00:00:00Z",
				},
			},
			"@scope/pkg": { time: { "1.0.0": "2026-11-09T12:00:00Z" } },
		})[name] ?? null;

	it("keeps an exclusion still inside the window", async () => {
		const errs = await findStaleExclusions(
			[
				{ entry: "lodash@4.17.22", line: 3 },
				{ entry: "@scope/pkg@1.0.0", line: 4 },
			],
			"f",
			{ now, fetchJson },
		);
		assert.deepEqual(errs, []);
	});

	it("rejects an exclusion older than the window", async () => {
		const errs = await findStaleExclusions(
			[{ entry: "lodash@4.17.21", line: 3 }],
			"f",
			{ now, fetchJson },
		);
		assert.deepEqual(rules(errs), ["exclusion-stale"]);
	});

	it("rejects an exclusion of a version that does not exist", async () => {
		const errs = await findStaleExclusions(
			[{ entry: "nope@1.0.0", line: 3 }],
			"f",
			{ now, fetchJson },
		);
		assert.deepEqual(rules(errs), ["exclusion-unknown"]);
	});
});
