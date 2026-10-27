#!/usr/bin/env node
// ABIP-7 exact-version check (openspec: dependency-pinning).
//
//   node scripts/check-pinned-versions.mjs   check every package.json and both pnpm override maps
//
// Every dependencies / devDependencies / optionalDependencies entry is an exact version. So is every
// peerDependencies entry, except in the libraries this repo publishes (packages/* with
// publishConfig, not private), whose peers keep semver ranges so integrators choose their own viem
// or react. Override values are exact too; an override's selector may keep the range that scopes it.
// Transitive ranges are the lockfile's job and out of scope. No dependencies, no network.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const WORKSPACES = [
	"pnpm-workspace.yaml",
	"services/custom-example/pnpm-workspace.yaml",
];
const FIELDS = [
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
];

const EXACT = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
const GIT_SHA = /^(github:|git\+(https|ssh):\/\/|git:\/\/).+#[0-9a-f]{40}$/;

/** Whether a manifest specifier is an exact, drift-free reference. */
export function isPinned(spec) {
	if (EXACT.test(spec)) return true;
	// workspace: and catalog: resolve to exact versions at install and publish time (ABIP-7 §4).
	if (spec.startsWith("workspace:") || spec.startsWith("catalog:")) return true;
	// An npm alias is pinned when the aliased version is.
	const alias = spec.match(/^npm:(?:@[^/@]+\/)?[^@]+@(.+)$/);
	if (alias) return EXACT.test(alias[1]);
	return GIT_SHA.test(spec);
}

/** A library this repo publishes: the exemption for peer-dependency ranges applies to it. */
export function isPublishedLibrary(manifest, file) {
	return (
		/^packages\/[^/]+\/package\.json$/.test(file) &&
		!manifest.private &&
		Boolean(manifest.publishConfig)
	);
}

/** Non-exact entries in one package.json. */
export function checkManifest(manifest, file) {
	const errs = [];
	const published = isPublishedLibrary(manifest, file);
	for (const field of FIELDS) {
		for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
			if (field === "peerDependencies" && published) continue;
			if (!isPinned(spec)) {
				errs.push({
					file,
					rule: "not-exact",
					message: `${field}.${name} is "${spec}"; ABIP-7 requires an exact version`,
				});
			}
		}
	}
	return errs;
}

/** The `overrides:` map of a pnpm-workspace.yaml (flat YAML: one quoted or bare `key: value` per line). */
export function parseOverrides(text) {
	const out = [];
	let inOverrides = false;
	text.split("\n").forEach((raw, i) => {
		const line = raw.replace(/\r$/, "");
		if (/^\s*(#|$)/.test(line)) return;
		if (/^\S/.test(line)) {
			inOverrides = /^overrides:\s*$/.test(line);
			return;
		}
		if (!inOverrides) return;
		const m = line.match(/^\s+("[^"]+"|'[^']+'|[^:\s]+):\s*(.+?)\s*(#.*)?$/);
		if (m)
			out.push({
				key: m[1].slice(
					/^["']/.test(m[1]) ? 1 : 0,
					/^["']/.test(m[1]) ? -1 : undefined,
				),
				value: m[2].replace(/^(['"])(.*)\1$/, "$2"),
				line: i + 1,
			});
	});
	return out;
}

/** Non-exact override values in one workspace file. */
export function checkOverrides(text, file) {
	return parseOverrides(text)
		.filter((o) => !isPinned(o.value))
		.map((o) => ({
			file,
			line: o.line,
			rule: "override-not-exact",
			message: `override "${o.key}" is "${o.value}"; ABIP-7 requires an exact version`,
		}));
}

function manifests() {
	return execFileSync("git", ["ls-files", "package.json", "**/package.json"], {
		cwd: ROOT,
		encoding: "utf8",
	})
		.split("\n")
		.filter(
			(f) =>
				f &&
				!/^(vendor|packages\/contracts\/lib)\//.test(f) &&
				!f.includes("node_modules/"),
		);
}

function main() {
	const errs = [];
	for (const file of manifests()) {
		errs.push(
			...checkManifest(
				JSON.parse(readFileSync(resolve(ROOT, file), "utf8")),
				file,
			),
		);
	}
	for (const file of WORKSPACES) {
		errs.push(
			...checkOverrides(readFileSync(resolve(ROOT, file), "utf8"), file),
		);
	}
	for (const e of errs)
		console.error(
			`${e.file}${e.line ? `:${e.line}` : ""}: [${e.rule}] ${e.message}`,
		);
	if (errs.length) {
		console.error(
			`\n${errs.length} ABIP-7 violation(s). See docs/abip-compliance.md.`,
		);
		return 1;
	}
	console.log("ABIP-7: every manifest entry and override is pinned.");
	return 0;
}

if (resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = main();
}
