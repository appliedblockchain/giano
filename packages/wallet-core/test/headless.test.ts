/// <reference types="node" />
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * wallet-core is the headless entrypoint: a backend imports it in plain Node to build
 * accounts, decode calls and sign UserOperations. Nothing browser-only may reach it, so a
 * consumer never installs React, RainbowKit or a DOM shim to use it.
 */

const packageDir = join(__dirname, "..");
const distDir = join(packageDir, "dist");

type Manifest = {
	name: string;
	dependencies?: Record<string, string>;
	peerDependencies?: Record<string, string>;
	peerDependenciesMeta?: Record<string, { optional?: boolean }>;
	optionalDependencies?: Record<string, string>;
};

/** One dependency edge. `optional`: a consumer may run without it installed. */
type Edge = { name: string; from: string; optional: boolean };

const readManifest = (dir: string): Manifest =>
	JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as Manifest;

/** Packages that only make sense in a browser or a UI. */
const BROWSER_ONLY =
	/^(react|react-dom|react-native|preact|wagmi|jsdom|happy-dom)$|^react-|^@rainbow-me\/|^@wagmi\/|^@tanstack\/react-|^@appliedblockchain\/giano-(connector|wallet-kit|wallet-transport)$/;

/** Node's lookup: `<dir>/node_modules/<name>` for `dir` and each ancestor. */
function findPackageDir(name: string, fromDir: string): string | undefined {
	for (let dir = fromDir; ; dir = dirname(dir)) {
		if (basename(dir) !== "node_modules") {
			const candidate = join(dir, "node_modules", name);
			if (existsSync(join(candidate, "package.json")))
				return realpathSync(candidate);
		}
		if (dirname(dir) === dir) return undefined;
	}
}

/** The runtime edges of a package: dependencies, optional dependencies and peers. */
function edgesOf(dir: string): Edge[] {
	const manifest = readManifest(dir);
	const optionalPeers = manifest.peerDependenciesMeta ?? {};
	return [
		...Object.keys(manifest.dependencies ?? {}).map((name) => ({
			name,
			from: dir,
			optional: false,
		})),
		...Object.keys(manifest.optionalDependencies ?? {}).map((name) => ({
			name,
			from: dir,
			optional: true,
		})),
		...Object.keys(manifest.peerDependencies ?? {}).map((name) => ({
			name,
			from: dir,
			optional: optionalPeers[name]?.optional === true,
		})),
	];
}

/**
 * Every package a consumer of wallet-core may install, at every level of the tree. A missing
 * optional dependency or optional peer is skipped; an installed one is still checked.
 */
function installedClosure(): Set<string> {
	const names = new Set<string>();
	const visitedDirs = new Set<string>();
	const queue = edgesOf(packageDir);

	for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
		const { name, from, optional } = next;
		const dir = findPackageDir(name, from);
		if (dir === undefined) {
			if (optional) continue;
			throw new Error(`${name} is not installed (needed by ${from})`);
		}
		names.add(name);
		if (visitedDirs.has(dir)) continue;
		visitedDirs.add(dir);
		queue.push(...edgesOf(dir));
	}
	return names;
}

/** The package name of a bare import specifier: `viem/actions` → `viem`. */
const packageName = (specifier: string): string =>
	specifier
		.split("/")
		.slice(0, specifier.startsWith("@") ? 2 : 1)
		.join("/");

describe("headless entrypoint", () => {
	it("pulls in no browser, React or RainbowKit package, directly or transitively", () => {
		const closure = installedClosure();
		// A broken walk would find nothing and pass; the direct dependencies must be there.
		expect([...closure]).toEqual(expect.arrayContaining(["viem", "ox"]));
		expect([...closure].filter((name) => BROWSER_ONLY.test(name))).toEqual([]);
	});

	// CI builds wallet-core before its tests. Locally, `pnpm build` first.
	describe.skipIf(!existsSync(distDir) && !process.env.CI)("built dist", () => {
		it("imports only the packages its manifest declares", () => {
			const manifest = readManifest(packageDir);
			const declared = new Set(
				Object.keys({ ...manifest.dependencies, ...manifest.peerDependencies }),
			);
			for (const file of ["index.mjs", "index.js"]) {
				const source = readFileSync(join(distDir, file), "utf8");
				const imported = new Set(
					[
						...source.matchAll(
							// `from "x"`, `import "x"` (side effect only), `import("x")`, `require("x")`.
							/(?:\bfrom|\bimport\s*\(?|\brequire\()\s*["']([^"'.][^"']*)["']/g,
						),
					]
						.map((match) => match[1])
						.filter((specifier) => !specifier.startsWith("node:"))
						.map(packageName),
				);
				expect(imported.size, file).toBeGreaterThan(0);
				expect(
					[...imported].filter((name) => !declared.has(name)),
					file,
				).toEqual([]);
			}
		});

		it("loads and builds a signed UserOperation in plain Node with no DOM globals", () => {
			const output = execFileSync(
				process.execPath,
				[join(__dirname, "headless", "smoke.mjs")],
				{ cwd: packageDir, encoding: "utf8", stdio: "pipe" },
			);
			expect(output).toContain("wallet-core headless smoke: ok");
		});
	});
});
