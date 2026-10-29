import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
	checkManifest,
	checkOverrides,
	isPinned,
	parseOverrides,
} from "./check-pinned-versions.mjs";

const SHA = "0123456789abcdef0123456789abcdef01234567";
const rules = (errs) => errs.map((e) => e.rule);

describe("check-pinned-versions: specifiers", () => {
	for (const spec of [
		"2.21.55",
		"1.0.0-rc.1",
		"1.0.0+build.5",
		"workspace:*",
		"workspace:^",
		"catalog:",
		"catalog:react19",
		"npm:@scope/pkg@1.2.3",
		`github:owner/repo#${SHA}`,
		`git+https://github.com/owner/repo.git#${SHA}`,
	]) {
		it(`accepts ${spec}`, () => assert.equal(isPinned(spec), true));
	}

	for (const spec of [
		"^2.21.55",
		"~2.21.55",
		">=1.2.3",
		"<=1.2.3",
		">1.2.3",
		"<2.0.0",
		"*",
		"1.x",
		"1.2",
		"latest",
		"next",
		"canary",
		"^1.0.0 || ^2.0.0",
		"npm:pkg@^1.0.0",
		"github:owner/repo#main",
		"github:owner/repo#v1.2.3",
		"git+https://github.com/owner/repo.git",
		"file:../pkg",
		"https://example.com/pkg.tgz",
	]) {
		it(`rejects ${spec}`, () => assert.equal(isPinned(spec), false));
	}
});

describe("check-pinned-versions: manifests", () => {
	const library = {
		name: "@appliedblockchain/giano-wallet-core",
		publishConfig: { registry: "https://npm.pkg.github.com" },
		dependencies: { ox: "0.7.1" },
		devDependencies: { vitest: "4.1.11" },
		peerDependencies: { viem: "^2.31.0", react: ">=18" },
	};

	it("keeps a published library's peer ranges", () => {
		assert.deepEqual(
			checkManifest(library, "packages/wallet-core/package.json"),
			[],
		);
	});

	it("still requires a published library's devDependencies to be exact", () => {
		const m = {
			...library,
			devDependencies: { "@rainbow-me/rainbowkit": "^2.2.4" },
		};
		const errs = checkManifest(m, "packages/connector/package.json");
		assert.deepEqual(rules(errs), ["not-exact"]);
		assert.match(
			errs[0].message,
			/devDependencies\.@rainbow-me\/rainbowkit is "\^2\.2\.4"/,
		);
	});

	it("still requires a published library's dependencies to be exact", () => {
		const m = { ...library, dependencies: { zod: "^3.23.8" } };
		assert.deepEqual(
			rules(checkManifest(m, "packages/contracts/package.json")),
			["not-exact"],
		);
	});

	it("rejects a private package's peer range", () => {
		const m = { private: true, peerDependencies: { viem: "^2.31.0" } };
		assert.deepEqual(
			rules(checkManifest(m, "packages/internal/package.json")),
			["not-exact"],
		);
	});

	it("does not treat a non-packages/ manifest as a library", () => {
		const m = { publishConfig: {}, peerDependencies: { react: "^19.0.0" } };
		assert.deepEqual(
			rules(checkManifest(m, "services/wallet-web/package.json")),
			["not-exact"],
		);
	});

	it("rejects a service range and names field, package and specifier", () => {
		const errs = checkManifest(
			{ private: true, dependencies: { fastify: "^5.12.1" } },
			"services/wallet-api/package.json",
		);
		assert.equal(errs[0].file, "services/wallet-api/package.json");
		assert.match(errs[0].message, /dependencies\.fastify is "\^5\.12\.1"/);
	});

	it("checks optionalDependencies", () => {
		assert.deepEqual(
			rules(
				checkManifest(
					{ private: true, optionalDependencies: { fsevents: "~2.3.3" } },
					"e2e/package.json",
				),
			),
			["not-exact"],
		);
	});
});

describe("check-pinned-versions: overrides", () => {
	const yaml = [
		"packages:",
		'  - "packages/*"',
		"",
		"overrides:",
		'  human-id: "4.1.1"',
		"  # GHSA-… — a comment",
		'  "ws@>=8.0.0 <8.21.0": "8.21.0"',
		'  "lodash@<4.18.0": "^4.18.0"',
		"",
		"minimumReleaseAge: 10080",
		"allowBuilds:",
		"  esbuild: false",
	].join("\n");

	it("parses the map and stops at the next top-level key", () => {
		assert.deepEqual(
			parseOverrides(yaml).map((o) => [o.key, o.value]),
			[
				["human-id", "4.1.1"],
				["ws@>=8.0.0 <8.21.0", "8.21.0"],
				["lodash@<4.18.0", "^4.18.0"],
			],
		);
	});

	it("keeps a ranged selector and rejects a caret value, naming the key and line", () => {
		const errs = checkOverrides(yaml, "pnpm-workspace.yaml");
		assert.deepEqual(
			errs.map((e) => [e.line, e.rule]),
			[[8, "override-not-exact"]],
		);
		assert.match(errs[0].message, /"lodash@<4\.18\.0"/);
	});
});
