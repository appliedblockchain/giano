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

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
	"packages/contracts/export.sarif.sarifexplorer",
	".gitleaksignore",
];

// A source comment changes the contract metadata hash, and so the CREATE2 addresses.
const IN_SOURCE_SUPPRESSION = /slither-disable|aderyn-ignore|aderyn-fp/;

// Slither keys that only set scope or output. Anything else (detectors_to_exclude, exclude_high,
// triage settings, …) would hide findings without a register entry. `//` holds the reasons.
export const SLITHER_SCOPE_KEYS = [
	"//",
	"filter_paths",
	"exclude_dependencies",
	"exclude_informational",
	"exclude_optimization",
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
	sha256: (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v),
	ghsa: (v) =>
		typeof v === "string" && /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/.test(v),
	workspace: (v) => WORKSPACES.includes(v),
};

// The finding identifier each tool's entries use (design D2). An entry's `match` has exactly the
// keys of one shape. A gitleaks entry can instead name the allowlist in .gitleaks.toml it covers.
export const MATCH_SHAPES = {
	slither: [{ check: "string", id: "sha256" }],
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
	if (entry.id !== undefined && !/^AF-\d{3}$/.test(entry.id))
		err("bad-id", `id '${entry.id}' is not AF- followed by three digits`);
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
	if (typeof entry.owner === "string" && /,|&|\/|\band\b/.test(entry.owner))
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

/** slither.config.json may set scope and output only (design D3). */
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
	return Object.keys(config)
		.filter((key) => !SLITHER_SCOPE_KEYS.includes(key))
		.map((key) => ({
			file,
			line: 1,
			rule: "config-suppression",
			message: `'${key}' is not a scope setting. A JSON config cannot name a register entry, so record each accepted finding in ${REGISTER_PATH} instead`,
		}));
}

// The register check reads aderyn.toml and .gitleaks.toml without a TOML library. It reads a plain
// subset of TOML and reports every line outside that subset, so no TOML form (a quoted name, a
// dotted key, an inline table, a multi-line string) can hide a setting from the check.

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

const ADERYN_SCOPE_KEYS = ["version", "root", "src", "include", "exclude"];

/** aderyn.toml may set scope only: the top-level scope keys, one line each. Anything else could turn detectors off. */
export function checkAderynConfig(text, file = ADERYN_CONFIG) {
	const errs = [];
	// A key after any table header belongs to that table, so it is not a top-level key.
	let inTable = false;
	for (const l of tomlLines(text)) {
		if (l.kind === "header") inTable = true;
		if (
			l.kind === "key" &&
			!inTable &&
			l.path.length === 1 &&
			ADERYN_SCOPE_KEYS.includes(l.path[0]) &&
			!l.code.includes("{")
		)
			continue;
		const what =
			l.kind === "header"
				? `Table [${l.path.join(".")}]`
				: l.kind === "key"
					? `Key '${l.path.join(".")}'${inTable ? " inside a table" : ""}`
					: l.kind === "other"
						? "A value that continues across lines"
						: l.why;
		errs.push({
			file,
			line: l.line,
			rule:
				l.kind === "header" || l.kind === "key"
					? "config-suppression"
					: "unsupported-config",
			message: `${what} is not allowed. This file sets scope only: the top-level keys ${ADERYN_SCOPE_KEYS.join(", ")}, each on one line. Detectors stay on; record each accepted finding in ${REGISTER_PATH} instead`,
		});
	}
	return errs;
}

const ALLOWLIST_NAME = /^allowlists?$/;

/**
 * Every allowlist in .gitleaks.toml is a table whose description names a gitleaks register entry
 * for this file (`allowlistIds`); no rule is disabled.
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
			message: `${what} is not supported here. The register check reads a plain subset of TOML: write each allowlist as an [allowlist], [[allowlists]] or [[rules.allowlists]] table`,
		});
	const blocks = [];
	let current = null;
	for (const l of tomlLines(text)) {
		if (l.kind === "unsupported") {
			unsupported(l.line, l.why);
			continue;
		}
		if (l.kind === "header") {
			const at = l.path.findIndex((s) => ALLOWLIST_NAME.test(s));
			current = null;
			if (at === -1) continue;
			if (at !== l.path.length - 1) {
				unsupported(l.line, `Table [${l.path.join(".")}]`);
				continue;
			}
			current = { header: l.path.join("."), line: l.line, description: null };
			blocks.push(current);
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
		const description = l.value.match(/^(["'])(.*)\1$/);
		if (current && l.path.length === 1 && l.path[0] === "description")
			current.description = description ? description[2] : "";
	}
	for (const block of blocks) {
		const named = (block.description ?? "").match(/AF-\d{3}/g) ?? [];
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
	const slither = read(SLITHER_CONFIG);
	if (slither !== null) errs.push(...checkSlitherConfig(slither));
	const aderyn = read(ADERYN_CONFIG);
	if (aderyn !== null) errs.push(...checkAderynConfig(aderyn));
	const gitleaks = read(GITLEAKS_CONFIG);
	if (gitleaks !== null)
		errs.push(...checkGitleaksConfig(gitleaks, allowlistIds));
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

function requireArray(value, what) {
	if (!Array.isArray(value)) throw new ReportError(`${what} is not an array`);
	return value;
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
		return requireArray(
			report.results.detectors ?? [],
			"results.detectors",
		).map((d) => ({
			key: { check: d.check, id: d.id },
			gating: SLITHER_GATE.includes(
				requireSeverity(
					d.impact,
					SLITHER_IMPACTS,
					`Slither finding ${d.check}`,
				),
			),
			label: `${d.check} (${d.impact}) at ${d.first_markdown_element ?? "unknown location"}`,
		}));
	},
	aderyn(report) {
		if (
			!isObject(report) ||
			!isObject(report.high_issues) ||
			!isObject(report.low_issues)
		)
			throw new ReportError("Aderyn report has no high_issues and low_issues");
		const instances = (issues, gating) =>
			requireArray(issues.issues, "issues").flatMap((issue) =>
				requireArray(issue.instances, `${issue.detector_name} instances`).map(
					(x) => ({
						key: {
							detector_name: issue.detector_name,
							contract_path: x.contract_path,
							line_no: x.line_no,
						},
						gating,
						label: `${issue.detector_name} (${gating ? "High" : "Low"}) at ${x.contract_path}:${x.line_no}`,
					}),
				),
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
		return Object.values(report.advisories).map((a) => ({
			key: { workspace, ghsa: a.github_advisory_id ?? `npm-advisory-${a.id}` },
			gating: PNPM_GATE.includes(
				requireSeverity(
					a.severity,
					PNPM_SEVERITIES,
					`pnpm advisory ${a.github_advisory_id ?? a.id}`,
				),
			),
			label: `${a.module_name} ${a.github_advisory_id ?? a.id} (${a.severity}) in workspace ${workspace}`,
		}));
	},
	trivy(report, { image }) {
		if (!isObject(report) || typeof report.SchemaVersion !== "number")
			throw new ReportError("Trivy report has no SchemaVersion");
		return requireArray(report.Results ?? [], "Results").flatMap((r) =>
			requireArray(r.Vulnerabilities ?? [], "Vulnerabilities").map((v) => ({
				key: { image, package: v.PkgName, vulnerability: v.VulnerabilityID },
				gating:
					TRIVY_GATE.includes(
						requireSeverity(
							v.Severity,
							TRIVY_SEVERITIES,
							`Trivy finding ${v.VulnerabilityID}`,
						),
					) && Boolean(v.FixedVersion),
				label: `${v.PkgName} ${v.InstalledVersion} ${v.VulnerabilityID} (${v.Severity}${v.FixedVersion ? `, fixed in ${v.FixedVersion}` : ", no fix"}) in ${image} ${r.Target}`,
			})),
		);
	},
	gitleaks(report) {
		// The label never includes the secret, only where it is.
		return requireArray(report, "gitleaks report").map((f) => ({
			key: { fingerprint: f.Fingerprint },
			gating: true,
			label: `${f.RuleID} in ${f.File}:${f.StartLine} (commit ${String(f.Commit ?? "").slice(0, 12)})`,
		}));
	},
};

const matches = (entry, key) =>
	Object.entries(entry.match).every(([k, v]) => key[k] === v);

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
	for (const finding of findings) {
		const candidates = own.filter((e) => matches(e, finding.key));
		const entry = candidates.find((e) => usable.has(e));
		if (entry) {
			result.accepted.push({ entry: entry.id, label: finding.label });
		} else if (!finding.gating) {
			result.belowGate++;
		} else {
			const stale = candidates[0];
			result.failures.push({
				label: finding.label,
				message: stale
					? isExpired(stale, today)
						? `matches ${stale.id}, but the entry ${expiredMessage(stale)}`
						: `matches ${stale.id}, but the entry is not valid (run the register check)`
					: `no entry in ${REGISTER_PATH}`,
			});
		}
	}
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
	let register;
	try {
		register = readJsonFile(resolve(root, REGISTER_PATH));
	} catch (e) {
		throw new ReportError(`cannot read ${REGISTER_PATH}: ${e.message}`);
	}
	const result = evaluateReport(
		args.tool,
		readFileSync(reportFile, "utf8"),
		register,
		today,
		args,
	);
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
			`\n${result.failures.length} open ${args.tool} finding(s). Fix each one, or record it in ${REGISTER_PATH} (see security/README.md).`,
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
