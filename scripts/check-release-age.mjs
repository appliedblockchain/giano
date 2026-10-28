#!/usr/bin/env node
// ABIP-6 minimum package age check (openspec: dependency-security).
//
//   node scripts/check-release-age.mjs              check both pnpm workspaces, every workflow and Dockerfile
//   node scripts/check-release-age.mjs --registry   also fail on an exclusion older than the window (network)
//
// Both pnpm workspaces (the root and services/custom-example) must set minimumReleaseAge to at
// least seven days, and may exclude only exact versions (name@x.y.z) — never a package by name or
// scope, except our own @appliedblockchain/* scope (a recorded deviation from ABIP-6, see
// docs/abip-compliance.md). Every `pnpm install` in CI or in a Dockerfile must be frozen. No dependencies, and no
// registry access unless --registry is given, so it runs on fork PRs too.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// ABIP-6: 3 days is the floor; 7 is its SHOULD for projects handling financial transactions,
// which a wallet is (openspec/changes/apply-abips design D3).
export const MIN_RELEASE_AGE_MINUTES = 10080;
export const WORKSPACES = [
	"pnpm-workspace.yaml",
	"services/custom-example/pnpm-workspace.yaml",
];

// Deviation from ABIP-6 (docs/abip-compliance.md): our own releases are built and published by
// this repository's release.yml, so the quarantine window adds nothing for them. The only
// name-based exclusion allowed.
export const INTERNAL_SCOPE_EXCLUSION = "@appliedblockchain/*";

// `name@x.y.z` or `@scope/name@x.y.z`, with an optional pre-release suffix.
const EXACT_EXCLUSION =
	/^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;

const unquote = (s) =>
	s
		.replace(/\s+#.*$/, "")
		.trim()
		.replace(/^(['"])(.*)\1$/, "$2");

/** The two release-age keys of a pnpm-workspace.yaml (flat top-level YAML), with line numbers. */
export function parseReleaseAgeConfig(text) {
	const config = { minimumReleaseAge: null, line: null, excludes: [] };
	let inExcludes = false;
	text.split("\n").forEach((raw, i) => {
		const line = raw.replace(/\r$/, "");
		if (/^\s*(#|$)/.test(line)) return;
		const top = line.match(/^([A-Za-z][\w-]*):\s*(.*)$/);
		if (top) {
			inExcludes = top[1] === "minimumReleaseAgeExclude";
			if (top[1] === "minimumReleaseAge") {
				config.minimumReleaseAge = Number(unquote(top[2]));
				config.line = i + 1;
			}
			return;
		}
		const item = inExcludes && line.match(/^\s+-\s+(.*)$/);
		if (item) config.excludes.push({ entry: unquote(item[1]), line: i + 1 });
	});
	return config;
}

/** Violations of the release-age floor and the exclusion format in one workspace file. */
export function checkWorkspace(text, file) {
	const errs = [];
	const config = parseReleaseAgeConfig(text);
	if (config.minimumReleaseAge === null) {
		errs.push({
			file,
			line: 1,
			rule: "release-age-missing",
			message: "minimumReleaseAge is not set",
		});
	} else if (!(config.minimumReleaseAge >= MIN_RELEASE_AGE_MINUTES)) {
		errs.push({
			file,
			line: config.line,
			rule: "release-age-floor",
			message: `minimumReleaseAge is ${config.minimumReleaseAge}; ABIP-6 requires at least ${MIN_RELEASE_AGE_MINUTES} (7 days)`,
		});
	}
	for (const { entry, line } of config.excludes) {
		if (entry !== INTERNAL_SCOPE_EXCLUSION && !EXACT_EXCLUSION.test(entry)) {
			errs.push({
				file,
				line,
				rule: "exclusion-not-versioned",
				message: `'${entry}' exempts a package by name or scope; ABIP-6 allows only an exact version (name@x.y.z), and Giano's only deviation is '${INTERNAL_SCOPE_EXCLUSION}'`,
			});
		}
	}
	return errs;
}

/** `pnpm install` (or `pnpm i`) without --frozen-lockfile, outside comments. */
export function findUnfrozenInstalls(text, file) {
	const errs = [];
	text.split("\n").forEach((line, i) => {
		const code = line.trimStart().startsWith("#") ? "" : line;
		for (const m of code.matchAll(/\bpnpm\s+(install|i)\b([^;&|\n]*)/g)) {
			if (!/--frozen-lockfile\b/.test(m[2])) {
				errs.push({
					file,
					line: i + 1,
					rule: "unfrozen-install",
					message: "pnpm install without --frozen-lockfile",
				});
			}
		}
	});
	return errs;
}

/** Version-specific exclusions whose version is already older than the window, or does not exist. */
export async function findStaleExclusions(
	excludes,
	file,
	{ now = Date.now(), fetchJson = registryJson } = {},
) {
	const errs = [];
	for (const { entry, line } of excludes) {
		if (!EXACT_EXCLUSION.test(entry)) continue;
		const at = entry.lastIndexOf("@");
		const [name, version] = [entry.slice(0, at), entry.slice(at + 1)];
		const published = (await fetchJson(name))?.time?.[version];
		if (!published) {
			errs.push({
				file,
				line,
				rule: "exclusion-unknown",
				message: `${entry} is not a published version`,
			});
		} else if (now - Date.parse(published) > MIN_RELEASE_AGE_MINUTES * 60_000) {
			errs.push({
				file,
				line,
				rule: "exclusion-stale",
				message: `${entry} was published ${published}, more than 7 days ago; remove the exclusion`,
			});
		}
	}
	return errs;
}

async function registryJson(name) {
	const res = await fetch(
		`https://registry.npmjs.org/${name.replace("/", "%2F")}`,
	);
	return res.ok ? res.json() : null;
}

function installFiles() {
	return execFileSync(
		"git",
		["ls-files", ".github/workflows/*.yml", "*Dockerfile*", "**/Dockerfile*"],
		{
			cwd: ROOT,
			encoding: "utf8",
		},
	)
		.split("\n")
		.filter(Boolean);
}

async function main(argv) {
	const errs = [];
	for (const file of WORKSPACES) {
		const text = readFileSync(resolve(ROOT, file), "utf8");
		errs.push(...checkWorkspace(text, file));
		if (argv.includes("--registry")) {
			errs.push(
				...(await findStaleExclusions(
					parseReleaseAgeConfig(text).excludes,
					file,
				)),
			);
		}
	}
	for (const file of [...new Set(installFiles())]) {
		errs.push(
			...findUnfrozenInstalls(readFileSync(resolve(ROOT, file), "utf8"), file),
		);
	}
	for (const e of errs)
		console.error(`${e.file}:${e.line}: [${e.rule}] ${e.message}`);
	if (errs.length) {
		console.error(
			`\n${errs.length} ABIP-6 violation(s). See docs/abip-compliance.md.`,
		);
		return 1;
	}
	console.log("ABIP-6: release-age floor, exclusions and frozen installs OK.");
	return 0;
}

if (resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = await main(process.argv.slice(2));
}
