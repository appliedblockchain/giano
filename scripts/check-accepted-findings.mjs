#!/usr/bin/env node
// Accepted-findings register and security report gate (openspec: ci-security-gates).
//
//   node scripts/check-accepted-findings.mjs
//       Register mode. Validates security/accepted-findings.json, rejects suppressions in the
//       security tool configs that do not name a register entry, and rejects in-source
//       suppression comments under packages/contracts/src.
//   node scripts/check-accepted-findings.mjs --tool <tool> --report <file> [--workspace <path>] [--image <name>]
//       Report mode. Reads one tool report and fails on every finding at or above the tool's gate
//       that no valid, unexpired register entry accepts. Fails when the report is missing, empty
//       or not a valid report, so a tool that could not run never passes.
//
// The security tools run without suppressions; this script is the one place that decides. No
// dependencies and no network access, so it runs on fork PRs too. See security/README.md.

import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const REGISTER_PATH = "security/accepted-findings.json";
export const MAX_ACCEPTANCE_DAYS = 180;
export const CONTRACTS_SRC = "packages/contracts/src";
export const SLITHER_CONFIG = "packages/contracts/slither.config.json";
export const ADERYN_CONFIG = "packages/contracts/aderyn.toml";
export const GITLEAKS_CONFIG = ".gitleaks.toml";
// The two pnpm workspaces, as `--workspace` and `match.workspace` name them.
export const WORKSPACES = [".", "services/custom-example"];

// Files a tool reads by itself to hide findings. They cannot carry an owner or an expiry, so the
// register replaces them.
export const SUPPRESSION_FILES = [
	"packages/contracts/slither.db.json",
	// Slither reads this when slither.config.json is missing.
	"packages/contracts/slither.conf.json",
	"packages/contracts/export.sarif.sarifexplorer",
	".gitleaksignore",
	".trivyignore",
	".trivyignore.yaml",
	"trivy.yaml",
];

// pnpm settings that hide advisories from `pnpm audit`, in each workspace's config files.
export const PNPM_CONFIG_FILES = [
	"pnpm-workspace.yaml",
	".npmrc",
	"package.json",
];
const PNPM_AUDIT_SETTING =
	/\b(auditConfig|audit-config|auditLevel|audit-level|ignoreGhsas|ignore-ghsas|ignoreCves|ignore-cves)\b|^\s*["']?ignore["']?\s*[:=]/m;

// A source comment changes the contract metadata hash, and so the CREATE2 addresses.
const IN_SOURCE_SUPPRESSION = /slither-disable|aderyn-ignore|aderyn-fp/;

// The fixed content of each Solidity tool config. Any other setting (detectors_to_exclude,
// exclude_high, a [detectors] table, …) would hide findings without a register entry, and a changed
// value could drop production code from the analysis. So the register check does not read what a
// config sets. It compares the whole file with the content below, apart from the reasons, and
// changing the scope means changing this script, in review.
// - include_paths keeps a Slither finding when any of its code is in packages/contracts/src outside
//   src/testing/. (filter_paths would drop a finding in src/ that also touches lib/.)
// - show_ignored_findings makes Slither ignore slither-disable comments and triage files in every
//   file, including imported dependencies.
// slither.config.json is this object plus a `//` member with the reasons, which Slither ignores.
export const SLITHER_SCOPE = {
	include_paths: "packages/contracts/src/(?!testing/)",
	exclude_informational: true,
	exclude_optimization: true,
	show_ignored_findings: true,
};
// aderyn.toml is these lines, in this order, plus blank lines and whole-line `#` comments with the
// reasons. A line that starts with `#` is a comment in TOML unless an earlier line opened a
// multi-line string or array, and none of these lines opens one.
export const ADERYN_LINES = [
	"version = 1",
	'root = "."',
	'src = "src"',
	'exclude = ["src/testing/"]',
];

const REQUIRED_FIELDS = [
	"id",
	"tool",
	"match",
	"severity",
	"location",
	"accepted",
	"expires",
	"owner",
	"reason",
];
const OPTIONAL_FIELDS = ["followUp"];
const SEVERITIES = [
	"informational",
	"low",
	"medium",
	"moderate",
	"high",
	"critical",
];

const FIELD_TYPES = {
	string: (v) => typeof v === "string" && v.trim() !== "",
	line: (v) => Number.isInteger(v) && v > 0,
	sha3_256: (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v),
	ghsa: (v) =>
		typeof v === "string" && /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/.test(v),
	workspace: (v) => WORKSPACES.includes(v),
};

// The finding identifier each tool's entries use (design D2). An entry's `match` has exactly the
// keys of one shape. A gitleaks entry can instead name the allowlist in .gitleaks.toml it covers.
export const MATCH_SHAPES = {
	slither: [{ check: "string", id: "sha3_256" }],
	aderyn: [
		{ detector_name: "string", contract_path: "string", line_no: "line" },
	],
	"pnpm-audit": [{ workspace: "workspace", ghsa: "ghsa" }],
	trivy: [{ image: "string", package: "string", vulnerability: "string" }],
	gitleaks: [{ fingerprint: "string" }, { allowlist: "string" }],
	codeql: [{ rule: "string", alert: "line" }],
};
export const TOOLS = Object.keys(MATCH_SHAPES);
// Tools that have a report mode. CodeQL alerts are read through the API by the weekly scan.
export const REPORT_TOOLS = [
	"slither",
	"aderyn",
	"pnpm-audit",
	"trivy",
	"gitleaks",
];

const DAY_MS = 86_400_000;

/** Milliseconds since the epoch for a valid `YYYY-MM-DD` calendar date, else null. */
export function parseDate(value) {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value))
		return null;
	const ms = Date.parse(`${value}T00:00:00Z`);
	if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== value)
		return null;
	return ms;
}

export const todayUtc = () => new Date().toISOString().slice(0, 10);

const isObject = (v) =>
	typeof v === "object" && v !== null && !Array.isArray(v);

function matchShapeOf(tool, match) {
	if (!isObject(match)) return null;
	const keys = Object.keys(match).sort().join(",");
	return (
		(MATCH_SHAPES[tool] ?? []).find(
			(shape) =>
				Object.keys(shape).sort().join(",") === keys &&
				Object.entries(shape).every(([k, type]) => FIELD_TYPES[type](match[k])),
		) ?? null
	);
}

const describeShapes = (tool) =>
	(MATCH_SHAPES[tool] ?? [])
		.map(
			(s) =>
				`{ ${Object.entries(s)
					.map(([k, t]) => `${k}: ${t}`)
					.join(", ")} }`,
		)
		.join(" or ");

/** Problems with one entry, ignoring expiry and duplicates. */
function entryErrors(entry, index) {
	const errs = [];
	const name =
		isObject(entry) && typeof entry.id === "string"
			? entry.id
			: `entry #${index + 1}`;
	const err = (rule, message) => errs.push({ entry: name, rule, message });
	if (!isObject(entry)) {
		err("bad-entry", "is not an object");
		return errs;
	}
	for (const field of REQUIRED_FIELDS) {
		const v = entry[field];
		if (
			v === undefined ||
			v === null ||
			(typeof v === "string" && v.trim() === "")
		)
			err("missing-field", `has no ${field}`);
	}
	for (const field of Object.keys(entry)) {
		if (!REQUIRED_FIELDS.includes(field) && !OPTIONAL_FIELDS.includes(field))
			err("unknown-field", `has an unknown field '${field}'`);
	}
	// typeof first: RegExp.test turns a value such as ["AF-001"] into the string "AF-001".
	if (
		entry.id !== undefined &&
		(typeof entry.id !== "string" || !/^AF-\d{3}$/.test(entry.id))
	)
		err(
			"bad-id",
			`id ${JSON.stringify(entry.id)} is not a string of AF- followed by three digits`,
		);
	if (entry.tool !== undefined && !TOOLS.includes(entry.tool))
		err("bad-tool", `tool '${entry.tool}' is not one of ${TOOLS.join(", ")}`);
	else if (
		entry.tool !== undefined &&
		entry.match !== undefined &&
		!matchShapeOf(entry.tool, entry.match)
	)
		err(
			"bad-match",
			`match for ${entry.tool} must be ${describeShapes(entry.tool)}`,
		);
	if (entry.severity !== undefined && !SEVERITIES.includes(entry.severity))
		err(
			"bad-severity",
			`severity '${entry.severity}' is not one of ${SEVERITIES.join(", ")}`,
		);
	for (const field of ["location", "owner", "reason", "followUp"]) {
		if (entry[field] !== undefined && typeof entry[field] !== "string")
			err("bad-field", `${field} is not a string`);
	}
	if (
		typeof entry.owner === "string" &&
		/[,&/;+|\r\n]|\b(and|or|teams?|group)\b/i.test(entry.owner)
	)
		err(
			"bad-owner",
			`owner '${entry.owner}' must name one person, not a list or a team`,
		);
	const accepted = parseDate(entry.accepted);
	const expires = parseDate(entry.expires);
	if (entry.accepted !== undefined && accepted === null)
		err("bad-date", `accepted '${entry.accepted}' is not a YYYY-MM-DD date`);
	if (entry.expires !== undefined && expires === null)
		err("bad-date", `expires '${entry.expires}' is not a YYYY-MM-DD date`);
	if (accepted !== null && expires !== null) {
		if (expires < accepted)
			err(
				"expiry-before-accepted",
				`expires ${entry.expires} is before accepted ${entry.accepted}`,
			);
		else if ((expires - accepted) / DAY_MS > MAX_ACCEPTANCE_DAYS)
			err(
				"expiry-too-far",
				`expires ${entry.expires} is more than ${MAX_ACCEPTANCE_DAYS} days after accepted ${entry.accepted}`,
			);
	}
	return errs;
}

const isExpired = (entry, today) =>
	typeof entry.expires === "string" && entry.expires < today;

// An entry takes effect on its assessment date, not before.
const isFuture = (entry, today) =>
	typeof entry.accepted === "string" && entry.accepted > today;

const expiredMessage = (entry) =>
	`expired on ${entry.expires} (owner: ${entry.owner}). The owner renews it with a new accepted date, reason and expiry, or removes it`;

/** Every register problem: entry fields, dates, duplicates, expiry and future acceptance. */
export function validateRegister(register, today) {
	if (!isObject(register) || !Array.isArray(register.entries))
		return [
			{
				entry: REGISTER_PATH,
				rule: "bad-register",
				message: 'must be an object with an "entries" array',
			},
		];
	const errs = [];
	const seen = new Set();
	register.entries.forEach((entry, i) => {
		const own = entryErrors(entry, i);
		errs.push(...own);
		if (!isObject(entry)) return;
		if (typeof entry.id === "string") {
			if (seen.has(entry.id))
				errs.push({
					entry: entry.id,
					rule: "duplicate-id",
					message: "is used by more than one entry",
				});
			seen.add(entry.id);
		}
		if (isExpired(entry, today))
			errs.push({
				entry: entry.id,
				rule: "expired",
				message: expiredMessage(entry),
			});
		if (isFuture(entry, today))
			errs.push({
				entry: entry.id,
				rule: "accepted-in-future",
				message: `accepted ${entry.accepted} is after today (${today}). Use the date of the assessment`,
			});
	});
	return errs;
}

/** Entries a report may use: well formed, accepted by today, not expired, and with a unique ID. */
export function usableEntries(register, today) {
	if (!isObject(register) || !Array.isArray(register.entries)) return [];
	const counts = new Map();
	for (const e of register.entries)
		if (isObject(e)) counts.set(e.id, (counts.get(e.id) ?? 0) + 1);
	return register.entries.filter(
		(e, i) =>
			isObject(e) &&
			entryErrors(e, i).length === 0 &&
			counts.get(e.id) === 1 &&
			!isExpired(e, today) &&
			!isFuture(e, today),
	);
}

/** In-source suppression comments, given [{ file, text }] for each Solidity file. */
export function findInSourceSuppressions(files) {
	const errs = [];
	for (const { file, text } of files) {
		text.split("\n").forEach((line, i) => {
			const m = line.match(IN_SOURCE_SUPPRESSION);
			if (m)
				errs.push({
					file,
					line: i + 1,
					rule: "in-source-suppression",
					message: `'${m[0]}' comment. A source comment changes the bytecode and the CREATE2 addresses; record the finding in ${REGISTER_PATH} instead`,
				});
		});
	}
	return errs;
}

/** slither.config.json is exactly SLITHER_SCOPE plus the `//` reasons (design D3). */
export function checkSlitherConfig(text, file = SLITHER_CONFIG) {
	let config;
	try {
		config = JSON.parse(text);
	} catch (e) {
		return [
			{
				file,
				line: 1,
				rule: "invalid-config",
				message: `is not valid JSON: ${e.message}`,
			},
		];
	}
	if (!isObject(config))
		return [
			{
				file,
				line: 1,
				rule: "invalid-config",
				message: "is not a JSON object",
			},
		];
	// JSON.parse and Slither's Python reader read the same values, and both keep the last of two
	// duplicate keys. Object.fromEntries keeps a `__proto__` key as an ordinary key.
	const scope = Object.fromEntries(
		Object.entries(config).filter(([key]) => key !== "//"),
	);
	if (isDeepStrictEqual(scope, SLITHER_SCOPE)) return [];
	const differs = [
		...new Set([...Object.keys(scope), ...Object.keys(SLITHER_SCOPE)]),
	].filter(
		(key) =>
			!Object.hasOwn(scope, key) ||
			!Object.hasOwn(SLITHER_SCOPE, key) ||
			!isDeepStrictEqual(scope[key], SLITHER_SCOPE[key]),
	);
	return [
		{
			file,
			line: 1,
			rule: "config-scope",
			message: `differs from the fixed scope in: ${differs.join(", ")}. Apart from "//" with the reasons, it must be exactly ${JSON.stringify(SLITHER_SCOPE)}. Detectors stay on; record each accepted finding in ${REGISTER_PATH} instead`,
		},
	];
}

/** aderyn.toml is exactly ADERYN_LINES plus blank lines and whole-line comments (design D3). */
export function checkAderynConfig(text, file = ADERYN_CONFIG) {
	const raw = text.split(/\r?\n/);
	const lines = raw
		.map((code, i) => ({ code, line: i + 1 }))
		.filter(({ code }) => !/^[ \t]*(#.*)?$/.test(code));
	for (let i = 0; i < Math.max(lines.length, ADERYN_LINES.length); i++) {
		if (lines[i]?.code === ADERYN_LINES[i]) continue;
		const found = lines[i] ? `has '${lines[i].code}'` : "ends";
		const expected =
			i < ADERYN_LINES.length ? `'${ADERYN_LINES[i]}'` : "nothing more";
		return [
			{
				file,
				line: lines[i]?.line ?? raw.length,
				rule: "config-scope",
				message: `${found} where it must have ${expected}. Apart from blank lines and whole-line # comments, it must be exactly these lines: ${ADERYN_LINES.join(" | ")}. Detectors stay on; record each accepted finding in ${REGISTER_PATH} instead`,
			},
		];
	}
	return [];
}

// The register check reads .gitleaks.toml without a TOML library. It reads a plain subset of TOML
// and reports every line outside that subset, so no TOML form (a quoted name, a dotted key, an
// inline table, a multi-line string) can hide a setting from the check.

/** One line with string contents blanked and the comment removed. `open` is true when a string does not close on the line. */
function scanTomlLine(raw) {
	let code = "";
	let quote = null;
	for (let i = 0; i < raw.length; i++) {
		const c = raw[i];
		if (quote) {
			if (quote[0] === '"' && c === "\\") {
				code += "  ";
				i++;
			} else if (raw.startsWith(quote, i)) {
				// A triple-quoted string ends at the next three quotes. '''' leaves it open.
				code += quote;
				i += quote.length - 1;
				quote = null;
			} else code += " ";
			continue;
		}
		if (c === "#") break;
		if (c === '"' || c === "'") {
			quote = raw.startsWith(c.repeat(3), i) ? c.repeat(3) : c;
			code += quote;
			i += quote.length - 1;
			continue;
		}
		code += c;
	}
	return { code, open: quote !== null };
}

/**
 * Each non-blank line as one of:
 * - { kind: "header", path }
 * - { kind: "key", path, code, value }: `code` is the value with strings blanked, `value` the raw value
 * - { kind: "other", code }: a value that continues from an earlier line
 * - { kind: "unsupported", why }
 */
function tomlLines(text) {
	const lines = [];
	text.split("\n").forEach((raw, i) => {
		const line = i + 1;
		const { code, open } = scanTomlLine(raw);
		const trimmed = code.trim();
		if (!trimmed) return;
		if (open) {
			lines.push({ line, kind: "unsupported", why: "A multi-line string" });
			return;
		}
		const header = trimmed.match(
			/^\[\[\s*([^[\]]*?)\s*\]\]$|^\[\s*([^[\]]*?)\s*\]$/,
		);
		if (header) {
			const name = header[1] ?? header[2];
			lines.push(
				/["']/.test(name)
					? { line, kind: "unsupported", why: "A quoted table name" }
					: {
							line,
							kind: "header",
							path: name.split(".").map((s) => s.trim()),
						},
			);
			return;
		}
		const eq = code.indexOf("=");
		if (eq > 0 && !/[[\]{},]/.test(code.slice(0, eq))) {
			const key = code.slice(0, eq).trim();
			lines.push(
				/["']/.test(key)
					? { line, kind: "unsupported", why: "A quoted key" }
					: {
							line,
							kind: "key",
							path: key.split(".").map((s) => s.trim()),
							code: code.slice(eq + 1).trim(),
							value: raw.slice(eq + 1, code.length).trim(),
						},
			);
			return;
		}
		lines.push({ line, kind: "other", code: trimmed });
	});
	return lines;
}

const ALLOWLIST_NAME = /^allowlists?$/;

/**
 * .gitleaks.toml keeps every default rule and hides findings only through register entries:
 * - it extends the default rules (`[extend]` with `useDefault = true`), with no other base config;
 * - it has no custom rules, which could replace or weaken a default rule;
 * - every allowlist is a table whose description names a gitleaks register entry for this file
 *   (`allowlistIds`);
 * - no rule is disabled.
 */
export function checkGitleaksConfig(
	text,
	allowlistIds,
	file = GITLEAKS_CONFIG,
) {
	const errs = [];
	const unsupported = (line, what) =>
		errs.push({
			file,
			line,
			rule: "unsupported-config",
			message: `${what} is not supported here. The register check reads a plain subset of TOML: write each allowlist as an [allowlist] or [[allowlists]] table`,
		});
	const notAllowed = (line, what) =>
		errs.push({
			file,
			line,
			rule: "config-suppression",
			message: `${what} is not allowed. This file may contain only a top-level title, [extend] with useDefault = true, and allowlist tables, so every default rule stays on`,
		});
	const blocks = [];
	let current = null;
	// "top" before any table, then "extend", "allowlist" or "other".
	let section = "top";
	let usesDefault = false;
	for (const l of tomlLines(text)) {
		if (l.kind === "unsupported") {
			unsupported(l.line, l.why);
			continue;
		}
		if (l.kind === "header") {
			const name = l.path.join(".");
			current = null;
			section = "other";
			if (name === "extend") section = "extend";
			else if (l.path.length === 1 && ALLOWLIST_NAME.test(name)) {
				section = "allowlist";
				current = { header: name, line: l.line, description: null };
				blocks.push(current);
			} else if (l.path.some((s) => ALLOWLIST_NAME.test(s)))
				unsupported(l.line, `Table [${name}]`);
			else notAllowed(l.line, `Table [${name}]`);
			continue;
		}
		if (l.code.includes("{")) {
			unsupported(l.line, "An inline table");
			continue;
		}
		if (l.kind !== "key") continue;
		if (l.path.includes("disabledRules")) {
			errs.push({
				file,
				line: l.line,
				rule: "config-suppression",
				message: `disabledRules turns rules off without a register entry. Use an allowlist whose description names an entry`,
			});
			continue;
		}
		if (l.path.some((s) => ALLOWLIST_NAME.test(s))) {
			unsupported(l.line, `Key '${l.path.join(".")}'`);
			continue;
		}
		const key = l.path.join(".");
		if (section === "top" && key !== "title") {
			notAllowed(l.line, `Top-level key '${key}'`);
			continue;
		}
		if (section === "extend") {
			if (key === "useDefault" && l.code === "true") usesDefault = true;
			else notAllowed(l.line, `'${key} = ${l.value}' in [extend]`);
			continue;
		}
		const description = l.value.match(/^(["'])(.*)\1$/);
		if (current && l.path.length === 1 && l.path[0] === "description")
			current.description = description ? description[2] : "";
	}
	if (!usesDefault)
		errs.push({
			file,
			line: 1,
			rule: "missing-default-rules",
			message:
				"has no [extend] table with useDefault = true. Without it, gitleaks does not run its default rules",
		});
	// Each allowlist starts its description with the one entry that accepts it, and each entry
	// accepts one allowlist, so one assessment cannot cover other allowlists.
	const used = new Map();
	for (const block of blocks) {
		const named = (block.description ?? "").match(/\bAF-\d{3}\b/g) ?? [];
		if (named.length === 1 && block.description.startsWith(named[0])) {
			if (used.has(named[0]))
				errs.push({
					file,
					line: block.line,
					rule: "suppression-without-entry",
					message: `[${block.header}] block names ${named[0]}, which already accepts the block on line ${used.get(named[0])}. Each allowlist needs its own entry`,
				});
			else used.set(named[0], block.line);
		} else if (named.length > 0) {
			errs.push({
				file,
				line: block.line,
				rule: "suppression-without-entry",
				message: `[${block.header}] block description must start with one entry ID and name no other (found ${named.join(", ")})`,
			});
			continue;
		}
		if (!named.some((id) => allowlistIds.has(id)))
			errs.push({
				file,
				line: block.line,
				rule: "suppression-without-entry",
				message: `[${block.header}] block has no description naming a valid, unexpired gitleaks entry in ${REGISTER_PATH} with match { "allowlist": "${GITLEAKS_CONFIG}" }${named.length ? ` (${named.join(", ")} is not one)` : ""}`,
			});
	}
	return errs;
}

function solidityFiles(root, dir) {
	const abs = resolve(root, dir);
	if (!existsSync(abs)) return [];
	return readdirSync(abs, { recursive: true, withFileTypes: true })
		.filter((d) => d.isFile() && d.name.endsWith(".sol"))
		.map((d) => relative(root, join(d.parentPath, d.name)))
		.sort();
}

// A symlink under src could bring in a file the in-source scan does not read.
function symlinks(root, dir) {
	const abs = resolve(root, dir);
	if (!existsSync(abs)) return [];
	return readdirSync(abs, { recursive: true, withFileTypes: true })
		.filter((d) => d.isSymbolicLink())
		.map((d) => relative(root, join(d.parentPath, d.name)))
		.sort();
}

// Every key in a JSON value, at any depth, with JSON escapes already decoded.
const jsonKeys = (value) =>
	isObject(value)
		? Object.entries(value).flatMap(([k, v]) => [k, ...jsonKeys(v)])
		: Array.isArray(value)
			? value.flatMap(jsonKeys)
			: [];
const PNPM_AUDIT_KEY =
	/^(auditConfig|audit-config|auditLevel|audit-level|ignoreGhsas|ignore-ghsas|ignoreCves|ignore-cves)$/;

/** pnpm settings that hide advisories, in each workspace's config files. */
export function checkPnpmAuditSettings(files) {
	const errs = [];
	for (const { file, text } of files) {
		// An escaped key ("\x61uditConfig") reads as auditConfig to pnpm but not to a text match, so a
		// YAML file may hold no escape, and package.json keys are read after JSON decoding.
		if (file.endsWith(".yaml") && text.includes("\\"))
			errs.push({
				file,
				line: text.slice(0, text.indexOf("\\")).split("\n").length,
				rule: "suppression-setting",
				message:
					"has a backslash escape. Write every key and value without escapes, so the check can read them",
			});
		if (file.endsWith("package.json")) {
			let keys = [];
			try {
				keys = jsonKeys(JSON.parse(text));
			} catch {}
			for (const key of keys.filter((k) => PNPM_AUDIT_KEY.test(k)))
				errs.push({
					file,
					line: 1,
					rule: "suppression-setting",
					message: `'${key}' hides advisories from pnpm audit without an owner or an expiry. Record each accepted advisory in ${REGISTER_PATH} instead`,
				});
			continue;
		}
		text.split("\n").forEach((line, i) => {
			const m = line.match(PNPM_AUDIT_SETTING);
			if (m)
				errs.push({
					file,
					line: i + 1,
					rule: "suppression-setting",
					message: `'${m[0].trim()}' hides advisories from pnpm audit without an owner or an expiry. Record each accepted advisory in ${REGISTER_PATH} instead`,
				});
		});
	}
	return errs;
}

function readJsonFile(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

/** Register mode: every problem in the register, the tool configs and the contract sources. */
export function checkRepository(root, today) {
	const errs = [];
	const registerFile = resolve(root, REGISTER_PATH);
	let register = null;
	// Any value that parses is validated, including null, false, 0 and "".
	let parsed = false;
	if (!existsSync(registerFile)) {
		errs.push({
			file: REGISTER_PATH,
			rule: "missing-register",
			message: "does not exist",
		});
	} else {
		try {
			register = readJsonFile(registerFile);
			parsed = true;
		} catch (e) {
			errs.push({
				file: REGISTER_PATH,
				rule: "bad-register",
				message: `is not valid JSON: ${e.message}`,
			});
		}
	}
	if (parsed)
		for (const e of validateRegister(register, today))
			errs.push({ file: REGISTER_PATH, ...e });
	// A gitleaks allowlist may cite only a usable gitleaks entry that accepts this allowlist file.
	const allowlistIds = new Set(
		usableEntries(register, today)
			.filter(
				(e) => e.tool === "gitleaks" && e.match.allowlist === GITLEAKS_CONFIG,
			)
			.map((e) => e.id),
	);

	errs.push(
		...findInSourceSuppressions(
			solidityFiles(root, CONTRACTS_SRC).map((file) => ({
				file,
				text: readFileSync(resolve(root, file), "utf8"),
			})),
		),
	);
	const read = (file) =>
		existsSync(resolve(root, file))
			? readFileSync(resolve(root, file), "utf8")
			: null;
	// Without its config, a tool falls back to its defaults or to another config file, so both
	// configs must exist while the contracts package does.
	const contracts = dirname(CONTRACTS_SRC);
	for (const [file, check] of [
		[SLITHER_CONFIG, checkSlitherConfig],
		[ADERYN_CONFIG, checkAderynConfig],
	]) {
		const text = read(file);
		if (text !== null) errs.push(...check(text));
		else if (existsSync(resolve(root, contracts)))
			errs.push({
				file,
				rule: "config-scope",
				message: "does not exist. The tool needs it to analyse the fixed scope",
			});
	}
	// If src itself, or a folder above it, is a symlink, the tools resolve the paths outside the
	// fixed scope and drop every finding.
	const src = resolve(root, CONTRACTS_SRC);
	if (
		existsSync(src) &&
		realpathSync(src) !== join(realpathSync(root), CONTRACTS_SRC)
	)
		errs.push({
			file: CONTRACTS_SRC,
			rule: "symlink",
			message:
				"or a folder above it is a symlink. The contract sources must be in a regular directory",
		});
	const gitleaks = read(GITLEAKS_CONFIG);
	if (gitleaks !== null)
		errs.push(...checkGitleaksConfig(gitleaks, allowlistIds));
	for (const file of symlinks(root, CONTRACTS_SRC))
		errs.push({
			file,
			rule: "symlink",
			message:
				"is a symlink. Every contract source under packages/contracts/src must be a regular file",
		});
	errs.push(
		...checkPnpmAuditSettings(
			WORKSPACES.flatMap((ws) => PNPM_CONFIG_FILES.map((f) => join(ws, f)))
				.filter((file) => existsSync(resolve(root, file)))
				.map((file) => ({
					file,
					text: readFileSync(resolve(root, file), "utf8"),
				})),
		),
	);
	for (const file of SUPPRESSION_FILES)
		if (existsSync(resolve(root, file)))
			errs.push({
				file,
				rule: "suppression-file",
				message: `hides findings without an owner or an expiry. Delete it and record each accepted finding in ${REGISTER_PATH}`,
			});
	return errs;
}

// --- Report mode -----------------------------------------------------------------------------

export class ReportError extends Error {}

const SLITHER_GATE = ["High"];
const PNPM_GATE = ["high", "critical"];
const TRIVY_GATE = ["HIGH", "CRITICAL"];

// Every severity each tool reports. Any other value, or none, makes the report invalid, so a
// malformed finding never counts as below the gate.
const SLITHER_IMPACTS = [
	"High",
	"Medium",
	"Low",
	"Informational",
	"Optimization",
];
const PNPM_SEVERITIES = ["info", "low", "moderate", "high", "critical"];
const TRIVY_SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function requireSeverity(value, allowed, what) {
	if (!allowed.includes(value))
		throw new ReportError(
			`${what} has severity ${JSON.stringify(value) ?? "undefined"}, not one of ${allowed.join(", ")}`,
		);
	return value;
}

/** An array whose every element is an object. */
function requireArray(value, what) {
	if (!Array.isArray(value)) throw new ReportError(`${what} is not an array`);
	value.forEach((v, i) => {
		if (!isObject(v)) throw new ReportError(`${what}[${i}] is not an object`);
	});
	return value;
}

// A list the tool leaves out when it is empty. Only an absent key means "none": null or any other
// value makes the report invalid.
const optionalArray = (value, what) =>
	value === undefined ? [] : requireArray(value, what);

// An Aderyn issue with no instance would add no finding, so a listed High would pass unseen.
function requireInstances(issue) {
	const instances = requireArray(
		issue.instances,
		`${issue.detector_name} instances`,
	);
	if (instances.length === 0)
		throw new ReportError(
			`Aderyn issue ${issue.detector_name} lists no instances`,
		);
	return instances;
}

// Each parser returns [{ key, gating, label }]. `key` holds the same fields as the tool's match
// shape, so an entry matches when every field of its `match` equals the finding's key.
export const PARSERS = {
	slither(report) {
		if (!isObject(report) || report.success !== true)
			throw new ReportError(
				`Slither did not succeed${isObject(report) && report.error ? `: ${report.error}` : ""}`,
			);
		if (!isObject(report.results))
			throw new ReportError("Slither report has no results object");
		return optionalArray(report.results.detectors, "results.detectors").map(
			(d) => ({
				key: { check: d.check, id: d.id },
				gating: SLITHER_GATE.includes(
					requireSeverity(
						d.impact,
						SLITHER_IMPACTS,
						`Slither finding ${d.check}`,
					),
				),
				severity: d.impact.toLowerCase(),
				label: `${d.check} (${d.impact}) at ${d.first_markdown_element ?? "unknown location"}`,
			}),
		);
	},
	aderyn(report) {
		if (
			!isObject(report) ||
			!isObject(report.high_issues) ||
			!isObject(report.low_issues)
		)
			throw new ReportError("Aderyn report has no high_issues and low_issues");
		// Aderyn 0.6.8 has two categories. Any other one (older versions had critical and medium)
		// would be ignored, so it makes the report invalid.
		const categories = Object.keys(report).filter((k) => k.endsWith("_issues"));
		if (categories.some((k) => k !== "high_issues" && k !== "low_issues"))
			throw new ReportError(
				`Aderyn report has unknown categories: ${categories.join(", ")}`,
			);
		for (const level of ["high", "low"]) {
			const issues = requireArray(
				report[`${level}_issues`].issues,
				`${level}_issues.issues`,
			);
			if (report.issue_count?.[level] !== issues.length)
				throw new ReportError(
					`Aderyn report counts ${report.issue_count?.[level]} ${level} issues but lists ${issues.length}`,
				);
		}
		const instances = (issues, gating) =>
			requireArray(issues.issues, "issues").flatMap((issue) =>
				requireInstances(issue).map((x) => ({
					key: {
						detector_name: issue.detector_name,
						contract_path: x.contract_path,
						line_no: x.line_no,
					},
					gating,
					severity: gating ? "high" : "low",
					label: `${issue.detector_name} (${gating ? "High" : "Low"}) at ${x.contract_path}:${x.line_no}`,
				})),
			);
		return [
			...instances(report.high_issues, true),
			...instances(report.low_issues, false),
		];
	},
	"pnpm-audit"(report, { workspace }) {
		if (!isObject(report))
			throw new ReportError("pnpm audit output is not a JSON object");
		if (report.error !== undefined)
			throw new ReportError(
				`pnpm audit could not audit: ${report.error?.message ?? JSON.stringify(report.error)}`,
			);
		if (!isObject(report.advisories) || !isObject(report.metadata))
			throw new ReportError("pnpm audit output has no advisories and metadata");
		const advisories = Object.values(report.advisories);
		advisories.forEach((a, i) => {
			if (!isObject(a))
				throw new ReportError(`pnpm advisory #${i + 1} is not an object`);
		});
		// The summary counts each advisory once. A gated advisory that is counted but not listed
		// was dropped from the list, so the report is invalid.
		for (const level of PNPM_GATE) {
			const counted = report.metadata.vulnerabilities?.[level];
			const listed = advisories.filter((a) => a.severity === level).length;
			if (counted !== listed)
				throw new ReportError(
					`pnpm audit counts ${counted} ${level} advisories but lists ${listed}`,
				);
		}
		return advisories.map((a) => ({
			key: { workspace, ghsa: a.github_advisory_id ?? `npm-advisory-${a.id}` },
			gating: PNPM_GATE.includes(
				requireSeverity(
					a.severity,
					PNPM_SEVERITIES,
					`pnpm advisory ${a.github_advisory_id ?? a.id}`,
				),
			),
			severity: a.severity,
			label: `${a.module_name} ${a.github_advisory_id ?? a.id} (${a.severity}) in workspace ${workspace}`,
		}));
	},
	trivy(report, { image }) {
		if (!isObject(report) || typeof report.SchemaVersion !== "number")
			throw new ReportError("Trivy report has no SchemaVersion");
		return optionalArray(report.Results, "Results").flatMap((r) =>
			optionalArray(r.Vulnerabilities, "Vulnerabilities").map((v) => ({
				key: { image, package: v.PkgName, vulnerability: v.VulnerabilityID },
				gating:
					TRIVY_GATE.includes(
						requireSeverity(
							v.Severity,
							TRIVY_SEVERITIES,
							`Trivy finding ${v.VulnerabilityID}`,
						),
					) && Boolean(v.FixedVersion),
				severity: v.Severity.toLowerCase(),
				label: `${v.PkgName} ${v.InstalledVersion} ${v.VulnerabilityID} (${v.Severity}${v.FixedVersion ? `, fixed in ${v.FixedVersion}` : ", no fix"}) in ${image} ${r.Target}`,
			})),
		);
	},
	gitleaks(report) {
		// gitleaks reports no severity: every finding gates. The label never includes the secret,
		// only where it is.
		return requireArray(report, "gitleaks report").map((f) => ({
			key: { fingerprint: f.Fingerprint },
			gating: true,
			label: `${f.RuleID} in ${f.File}:${f.StartLine} (commit ${String(f.Commit ?? "").slice(0, 12)})`,
		}));
	},
};

// Severity order across tools. An entry accepts a gating finding only up to the severity it was
// assessed at, so a finding the tool re-rates higher fails until the owner reassesses it.
const SEVERITY_RANK = {
	informational: 0,
	low: 1,
	medium: 2,
	moderate: 2,
	high: 3,
	critical: 4,
};
const covers = (entry, finding) =>
	!finding.gating ||
	finding.severity === undefined ||
	SEVERITY_RANK[entry.severity] >= SEVERITY_RANK[finding.severity];

const matches = (entry, key) =>
	Object.entries(entry.match).every(([k, v]) => key[k] === v);

// Tools whose findings change only when the contract source or the pinned tool version changes. For
// these, every entry must match a finding in each report. An entry that matches nothing fails, so the
// PR that fixes or moves a finding also removes or updates its entry. Otherwise a stale Aderyn entry,
// which matches only a detector, a file and a line, would later accept a different finding that lands
// on the same line.
export const FULL_SCAN_TOOLS = ["slither", "aderyn"];

/**
 * Decides one report. Returns { accepted: [{ entry, label }], failures: [{ label, message }],
 * belowGate }. Throws ReportError when the report is missing, empty or not valid.
 */
export function evaluateReport(tool, text, register, today, options = {}) {
	if (!REPORT_TOOLS.includes(tool))
		throw new ReportError(`unknown tool '${tool}'`);
	if (typeof text !== "string" || text.trim() === "")
		throw new ReportError(
			"the report is empty: the tool did not produce a result",
		);
	let report;
	try {
		report = JSON.parse(text);
	} catch (e) {
		throw new ReportError(`the report is not valid JSON: ${e.message}`);
	}
	const findings = PARSERS[tool](report, options);
	const own = (register?.entries ?? []).filter(
		(e) => isObject(e) && e.tool === tool && isObject(e.match),
	);
	const usable = new Set(usableEntries(register, today));
	const result = { accepted: [], failures: [], belowGate: 0 };
	const matched = new Set();
	for (const finding of findings) {
		const candidates = own.filter((e) => matches(e, finding.key));
		for (const c of candidates) matched.add(c);
		const entry = candidates.find((e) => usable.has(e) && covers(e, finding));
		const outranked = candidates.find((e) => usable.has(e));
		if (entry) {
			result.accepted.push({ entry: entry.id, label: finding.label });
		} else if (!finding.gating) {
			result.belowGate++;
		} else {
			const stale = candidates[0];
			result.failures.push({
				label: finding.label,
				message: outranked
					? `matches ${outranked.id}, but the entry accepts ${outranked.severity} and the tool now reports ${finding.severity}. The owner reassesses the finding and updates the entry`
					: stale
						? isExpired(stale, today)
							? `matches ${stale.id}, but the entry ${expiredMessage(stale)}`
							: `matches ${stale.id}, but the entry is not valid (run the register check)`
						: `no entry in ${REGISTER_PATH}`,
			});
		}
	}
	if (FULL_SCAN_TOOLS.includes(tool))
		for (const e of own.filter((e) => !matched.has(e)))
			result.failures.push({
				label: `${e.id ?? "an entry"} in ${REGISTER_PATH}`,
				message: `matches no ${tool} finding in this report. Remove the entry if the finding is fixed, or update its match if the finding moved`,
			});
	return result;
}

// --- CLI -------------------------------------------------------------------------------------

export function parseArgs(argv) {
	const args = {};
	for (let i = 0; i < argv.length; i++) {
		const flag = argv[i];
		const name = {
			"--tool": "tool",
			"--report": "report",
			"--workspace": "workspace",
			"--image": "image",
		}[flag];
		if (!name || argv[i + 1] === undefined || argv[i + 1].startsWith("--"))
			throw new ReportError(`unexpected argument '${flag}'`);
		args[name] = argv[++i];
	}
	return args;
}

function reportMode(args, root, today) {
	if (!args.tool || !args.report)
		throw new ReportError("report mode needs --tool and --report");
	if (args.tool === "pnpm-audit" && !WORKSPACES.includes(args.workspace))
		throw new ReportError(
			`pnpm-audit needs --workspace, one of ${WORKSPACES.join(", ")}`,
		);
	if (args.tool === "trivy" && !args.image)
		throw new ReportError("trivy needs --image");
	const reportFile = resolve(args.report);
	if (!existsSync(reportFile))
		throw new ReportError(
			`report ${args.report} does not exist: the tool did not produce a result`,
		);
	let text;
	try {
		text = readFileSync(reportFile, "utf8");
	} catch (e) {
		throw new ReportError(`cannot read report ${args.report}: ${e.message}`);
	}
	let register;
	try {
		register = readJsonFile(resolve(root, REGISTER_PATH));
	} catch (e) {
		throw new ReportError(`cannot read ${REGISTER_PATH}: ${e.message}`);
	}
	const result = evaluateReport(args.tool, text, register, today, args);
	for (const a of result.accepted)
		console.log(`accepted  ${a.entry}  ${a.label}`);
	if (result.belowGate)
		console.log(
			`${result.belowGate} finding(s) below the ${args.tool} gate. They are in the report.`,
		);
	for (const f of result.failures)
		console.error(`FAIL  ${f.label}: ${f.message}`);
	if (result.failures.length) {
		console.error(
			`\n${result.failures.length} ${args.tool} problem(s). Fix each open finding or record it in ${REGISTER_PATH}, and remove or update each entry that matches nothing (see security/README.md).`,
		);
		return 1;
	}
	console.log(`${args.tool}: no open finding at or above the gate.`);
	return 0;
}

export function main(
	argv = process.argv.slice(2),
	{ root = ROOT, today = todayUtc() } = {},
) {
	try {
		if (argv.length) return reportMode(parseArgs(argv), root, today);
	} catch (e) {
		if (!(e instanceof ReportError)) throw e;
		console.error(`FAIL  ${e.message}`);
		return 1;
	}
	const errs = checkRepository(root, today);
	for (const e of errs)
		console.error(
			`${e.file}${e.line ? `:${e.line}` : ""}: [${e.rule}]${e.entry ? ` ${e.entry}` : ""} ${e.message}`,
		);
	if (errs.length) {
		console.error(
			`\n${errs.length} register problem(s). See security/README.md.`,
		);
		return 1;
	}
	console.log(
		`${REGISTER_PATH}: every entry is valid and unexpired, and no suppression bypasses it.`,
	);
	return 0;
}

if (
	process.argv[1] &&
	resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
	process.exitCode = main();
}
