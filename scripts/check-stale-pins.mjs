#!/usr/bin/env node
// Stale-pin report (openspec: dependency-freshness). Replaces Dependabot version updates.
//
//   node scripts/check-stale-pins.mjs   print a Markdown report; exit 1 when a pin is stale or a check failed
//
// Ported from the toolbox's weekly freshness run (appliedblockchain/toolbox, scripts/repo-checks).
// Every pin is compared with its latest qualifying release: the newest stable release published at
// least 7 days ago (ABIP-6). Pins covered:
//   - exact npm versions in every package.json of both workspaces (not overrides, which are
//     security floors, and not our own workspace packages);
//   - our own @appliedblockchain/* pins in services/custom-example, against the version of the
//     package in packages/* (the release this repository publishes; it needs no registry);
//   - every third-party action pinned to a commit SHA with its release as a trailing comment;
//   - the toolchains and CI tools pinned outside npm (TOOLS below).
// A pin may be held back openly by a row in docs/version-deferrals.md. A row past its review date
// no longer holds the pin. Reads the network; set GITHUB_TOKEN to raise the GitHub API rate limit.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EXACT, manifests } from "./check-pinned-versions.mjs";
import { MIN_RELEASE_AGE_MINUTES, registryUrl } from "./check-release-age.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFERRALS_FILE = "docs/version-deferrals.md";

// ---------------------------------------------------------------------------------------------
// Versions

const SEMVER =
	/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** `{ major, minor, patch, pre }` of a full semver version, or null. */
export function parseVersion(v) {
	const m = SEMVER.exec(String(v).trim());
	return m
		? { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ?? null }
		: null;
}

/** A stable release: full semver with no pre-release part. */
export const isStable = (v) => parseVersion(v)?.pre === null;

/**
 * A pin, which may be partial: `.nvmrc` holds `v24.22`, and setup-node installs the newest
 * 24.22.x. `precision` is the number of parts given (3 for a full version), or null.
 */
export function parsePin(v) {
	const full = parseVersion(v);
	if (full) return { ...full, precision: 3 };
	const m = /^v?(\d+)(?:\.(\d+))?$/.exec(String(v).trim());
	if (!m) return null;
	return {
		major: +m[1],
		minor: +(m[2] ?? 0),
		patch: 0,
		pre: null,
		precision: m[2] === undefined ? 1 : 2,
	};
}

/** Semver pre-release precedence; a release without one ranks above its pre-releases. */
function comparePre(a, b) {
	if (a === b) return 0;
	if (a === null) return 1;
	if (b === null) return -1;
	const x = a.split(".");
	const y = b.split(".");
	for (let i = 0; i < Math.max(x.length, y.length); i++) {
		if (x[i] === undefined) return -1;
		if (y[i] === undefined) return 1;
		const nx = /^\d+$/.test(x[i]);
		const ny = /^\d+$/.test(y[i]);
		if (nx && ny && Number(x[i]) !== Number(y[i]))
			return Number(x[i]) - Number(y[i]);
		if (nx !== ny) return nx ? -1 : 1;
		if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
	}
	return 0;
}

/** Compares two full versions, pre-releases included. */
export function compareVersions(a, b) {
	const x = parseVersion(a);
	const y = parseVersion(b);
	return (
		x.major - y.major ||
		x.minor - y.minor ||
		x.patch - y.patch ||
		comparePre(x.pre, y.pre)
	);
}

/** Whether `version` is newer than a pin allows. A partial pin (`24.22`) allows every 24.22.x. */
export function isBehind(pinned, version) {
	const p = parsePin(pinned);
	const v = parseVersion(version);
	for (const part of ["major", "minor", "patch"].slice(0, p.precision))
		if (v[part] !== p[part]) return v[part] > p[part];
	return p.precision === 3 && comparePre(p.pre, v.pre) < 0;
}

/** `major`, `minor` or `patch`: the size of the step from `pinned` to `latest`. */
export function updateType(pinned, latest) {
	const x = parsePin(pinned);
	const y = parseVersion(latest);
	if (!x || !y) return "?";
	if (x.major !== y.major) return "major";
	if (x.minor !== y.minor) return "minor";
	return "patch";
}

/**
 * The newest of `{ version, date, target? }` releases that are stable, old enough and (optionally)
 * in one major. A release with `target: false` counts only within a held major: it is history,
 * not a default upgrade target (a Node line that is no longer the Active LTS).
 */
export function newestQualifying(releases, cutoff, major) {
	return releases
		.filter((r) => isStable(r.version) && Date.parse(r.date) <= cutoff)
		.filter((r) =>
			major === undefined
				? r.target !== false
				: parseVersion(r.version).major === major,
		)
		.sort((a, b) => compareVersions(b.version, a.version))[0];
}

// ---------------------------------------------------------------------------------------------
// Release sources. `fetchJson(url)` is injected so the tests replay recorded responses.

const FETCH_TIMEOUT_MS = 30_000;
/** Waits before each retry of a network error, a timeout, a 5xx or a 429. */
const RETRY_DELAYS_MS = [2_000, 10_000];

export async function httpFetchJson(
	url,
	{
		fetchImpl = fetch,
		sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
	} = {},
) {
	const headers = {
		accept: "application/json",
		"user-agent": "giano-stale-pins",
	};
	const token = process.env.GITHUB_TOKEN;
	if (token && url.startsWith("https://api.github.com/"))
		headers.authorization = `Bearer ${token}`;
	for (let attempt = 0; ; attempt++) {
		let error;
		let retryable = true;
		try {
			const res = await fetchImpl(url, {
				headers,
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			});
			if (res.ok) return await res.json();
			error = new Error(`${url}: HTTP ${res.status}`);
			retryable = res.status >= 500 || res.status === 429;
		} catch (cause) {
			// A network error, the timeout or an unreadable body.
			error = new Error(`${url}: ${cause.message}`);
		}
		if (!retryable || attempt >= RETRY_DELAYS_MS.length) throw error;
		await sleep(RETRY_DELAYS_MS[attempt]);
	}
}

/**
 * Releases of an npm package. `time` still lists unpublished versions, so only those in
 * `versions` count, and a deprecated version is not a release to move to.
 */
export async function npmReleases(fetchJson, name) {
	const doc = await fetchJson(registryUrl(name));
	const versions = doc?.versions ?? {};
	return Object.entries(doc?.time ?? {})
		.filter(
			([version]) =>
				parseVersion(version) &&
				versions[version] !== undefined &&
				!versions[version].deprecated,
		)
		.map(([version, date]) => ({ version, date }));
}

const GITHUB_PAGE_SIZE = 100;
/** codeql-action and foundry publish many non-matching releases; every page is read, up to this. */
const GITHUB_MAX_PAGES = 30;

/** Releases of a GitHub repository, with `vX.Y.Z` (or `<prefix>X.Y.Z`) tags. Reads every page. */
export async function githubReleases(fetchJson, repo, tagPrefix = "v") {
	const releases = [];
	for (let page = 1; ; page++) {
		const batch = await fetchJson(
			`https://api.github.com/repos/${repo}/releases?per_page=${GITHUB_PAGE_SIZE}&page=${page}`,
		);
		releases.push(...batch);
		if (batch.length < GITHUB_PAGE_SIZE) break;
		if (page === GITHUB_MAX_PAGES)
			throw new Error(
				`${repo}: more than ${GITHUB_PAGE_SIZE * GITHUB_MAX_PAGES} releases (raise GITHUB_MAX_PAGES)`,
			);
	}
	return releases
		.filter(
			(r) => !r.draft && !r.prerelease && r.tag_name.startsWith(tagPrefix),
		)
		.map((r) => ({
			version: r.tag_name.slice(tagPrefix.length),
			date: r.published_at,
			tag: r.tag_name,
		}))
		.filter((r) => parseVersion(r.version));
}

/** Releases of a PyPI package; a release is dated by its first upload and skipped if yanked. */
export async function pypiReleases(fetchJson, name) {
	const doc = await fetchJson(`https://pypi.org/pypi/${name}/json`);
	return Object.entries(doc?.releases ?? {})
		.filter(([, files]) => files.length > 0 && !files.some((f) => f.yanked))
		.map(([version, files]) => ({
			version,
			date: files.map((f) => f.upload_time_iso_8601).sort()[0],
		}));
}

/**
 * Every Node.js release. Only those of the newest line in Active LTS on `today` (YYYY-MM-DD) are
 * upgrade targets; the rest stay available to a deferral that holds an older major.
 */
export async function nodeActiveLtsReleases(fetchJson, today) {
	const schedule = await fetchJson(
		"https://raw.githubusercontent.com/nodejs/Release/main/schedule.json",
	);
	const active = Object.entries(schedule)
		.filter(
			([, line]) =>
				line.lts !== undefined &&
				line.lts <= today &&
				line.end >= today &&
				(line.maintenance === undefined || line.maintenance > today),
		)
		.map(([name]) => Number(name.replace(/^v/, "")))
		.sort((a, b) => b - a)[0];
	const index = await fetchJson("https://nodejs.org/dist/index.json");
	return index
		.map((r) => ({
			version: r.version.replace(/^v/, ""),
			date: `${r.date}T00:00:00Z`,
		}))
		.filter((r) => parseVersion(r.version))
		.map((r) => ({ ...r, target: parseVersion(r.version).major === active }));
}

/** The commit a GitHub tag points at, for the report (an action is pinned by commit SHA). */
export async function tagCommit(fetchJson, repo, tag) {
	const commit = await fetchJson(
		`https://api.github.com/repos/${repo}/commits/${encodeURIComponent(tag)}`,
	);
	return commit?.sha;
}

// ---------------------------------------------------------------------------------------------
// Pins in this repository

const NPM_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"];

/**
 * Exact npm pins of the given manifests, as `{ name, pinned, where }`. A pin on one of `own`
 * (the names of this repository's packages) is returned with `own: true`.
 */
export function npmPins(manifests, own) {
	const pins = [];
	for (const { file, manifest } of manifests) {
		for (const field of NPM_FIELDS) {
			for (const [key, spec] of Object.entries(manifest[field] ?? {})) {
				let name = key;
				let version = spec;
				const alias = /^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/.exec(spec);
				if (alias) [, name, version] = alias;
				if (!EXACT.test(version)) continue; // workspace:, catalog:, git SHAs
				pins.push({ name, pinned: version, where: file, own: own.has(name) });
			}
		}
	}
	return pins;
}

const ACTION_PIN =
	/^\s*-?\s*uses:\s*([\w.-]+\/[\w.-]+)(?:\/[^@\s]*)?@[0-9a-f]{40}\b(?:\s+#\s*(v?\d[\w.+-]*))?/;

/**
 * Third-party actions pinned as `uses: owner/repo[/path]@<sha> # vX.Y.Z`, as `{ pins, problems }`.
 * One pinned to a SHA without a release comment cannot be compared, so it is a problem, not skipped.
 */
export function actionPins(text, file) {
	const pins = [];
	const problems = [];
	text.split("\n").forEach((line, i) => {
		const m = ACTION_PIN.exec(line);
		if (!m) return;
		const where = `${file}:${i + 1}`;
		if (m[2]) pins.push({ name: m[1], pinned: m[2].replace(/^v/, ""), where });
		else
			problems.push(
				`${where}: \`${m[1]}\` is pinned to a commit SHA without a \`# vX.Y.Z\` release comment`,
			);
	});
	return { pins, problems };
}

/** Releases a tool pin is compared with. */
const SOURCES = {
	npm: (fetchJson, s) => npmReleases(fetchJson, s.package),
	github: (fetchJson, s) => githubReleases(fetchJson, s.repo, s.tagPrefix),
	pypi: (fetchJson, s) => pypiReleases(fetchJson, s.package),
	"node-lts": (fetchJson, _s, today) => nodeActiveLtsReleases(fetchJson, today),
};

const FOUNDRY_IMAGE = "foundry-rs/foundry@sha256:[0-9a-f]{64}";

/**
 * Toolchains and CI tools pinned outside npm and actions. `files` are git pathspecs, or `grep` is
 * a regex selecting every tracked file that contains it; `pattern` captures the version (in its
 * first group that matched). Every match is one pin, so a tool pinned in two places is checked in
 * both. An entry that matches nothing is reported: its pin moved or changed shape. With `anchor`,
 * every occurrence of it outside a match is reported too: a copy of the pin with no version.
 */
export const TOOLS = [
	{
		name: "node",
		files: [".nvmrc"],
		pattern: /^v?(\d+(?:\.\d+){0,2})\s*$/m,
		source: { type: "node-lts" },
	},
	{
		name: "pnpm",
		files: ["package.json", "services/custom-example/package.json"],
		pattern: /"packageManager":\s*"pnpm@(\d+\.\d+\.\d+)/,
		source: { type: "npm", package: "pnpm" },
	},
	// Foundry moves together everywhere: e2e/devnet/state.json must match anvil's format.
	{
		name: "foundry",
		files: [".github/workflows/*.yml"],
		pattern:
			/foundry-toolchain@\S+[^\n]*\n(?:[^\n]*\n){0,8}?\s+version:\s*v(\d+\.\d+\.\d+)/,
		source: { type: "github", repo: "foundry-rs/foundry" },
	},
	// The image, pinned by digest wherever it appears, with its release in a `# vX.Y.Z` or
	// `// vX.Y.Z` comment at the end of the line or on a comment line just above.
	{
		name: "foundry",
		grep: FOUNDRY_IMAGE,
		anchor: new RegExp(FOUNDRY_IMAGE),
		pattern: new RegExp(
			`${FOUNDRY_IMAGE}["';,]*[ \\t]*(?:#|//)[ \\t]*v(\\d+\\.\\d+\\.\\d+)|^[ \\t]*(?:#|//)[^\\n]*\\bv(\\d+\\.\\d+\\.\\d+)\\b[^\\n]*\\n[^\\n]*${FOUNDRY_IMAGE}`,
			"m",
		),
		source: { type: "github", repo: "foundry-rs/foundry" },
	},
	{
		name: "foundry",
		files: [
			"e2e/devnet/generate-state.mjs",
			"e2e/devnet/upgrade-paymaster.mjs",
		],
		pattern: /PINNED_ANVIL_VERSION = "(\d+\.\d+\.\d+)"/,
		source: { type: "github", repo: "foundry-rs/foundry" },
	},
	{
		name: "gitleaks",
		files: [".github/workflows/*.yml"],
		pattern: /GITLEAKS_VERSION:\s*"?(\d+\.\d+\.\d+)/,
		source: { type: "github", repo: "gitleaks/gitleaks" },
	},
	{
		name: "trivy",
		files: [".github/workflows/*.yml"],
		pattern: /TRIVY_VERSION:\s*"?(\d+\.\d+\.\d+)/,
		source: { type: "github", repo: "aquasecurity/trivy" },
	},
	{
		name: "slither-analyzer",
		files: ["packages/contracts/requirements-ci.in"],
		pattern: /^slither-analyzer==(\d+\.\d+\.\d+)/m,
		source: { type: "pypi", package: "slither-analyzer" },
	},
];

const lineOf = (text, index) => text.slice(0, index).split("\n").length;
const globally = (re) =>
	new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);

/** Every match of a tool's pattern in one file, as `{ pins, problems }`. */
export function toolPins(tool, text, file) {
	const pins = [];
	const spans = [];
	for (const m of text.matchAll(globally(tool.pattern))) {
		const version = m.slice(1).find((g) => g !== undefined);
		pins.push({
			name: tool.name,
			pinned: version,
			where: `${file}:${lineOf(text, m.index + m[0].indexOf(version))}`,
		});
		spans.push([m.index, m.index + m[0].length]);
	}
	const problems = [];
	if (tool.anchor)
		for (const a of text.matchAll(globally(tool.anchor)))
			if (!spans.some(([from, to]) => a.index >= from && a.index < to))
				problems.push(
					`${file}:${lineOf(text, a.index)}: \`${tool.name}\` is pinned without its release (add a \`# vX.Y.Z\` or \`// vX.Y.Z\` comment on the line or the line above)`,
				);
	return { pins, problems };
}

// ---------------------------------------------------------------------------------------------
// Deferrals

const DEFERRAL_COLUMNS = [
	"Name",
	"Held version",
	"Reason",
	"Owner",
	"Review-by",
];

/** The furthest a deferral's review date may be (docs/version-deferrals.md). */
export const MAX_DEFERRAL_DAYS = 180;

/** A real calendar date written YYYY-MM-DD. */
function isCalendarDate(s) {
	if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
	const t = Date.parse(`${s}T00:00:00Z`);
	return !Number.isNaN(t) && new Date(t).toISOString().startsWith(s);
}

/** Rows of the deferral table, and the problems with it (a broken row holds nothing). */
export function parseDeferrals(text, file = DEFERRALS_FILE, now = Date.now()) {
	const latestReview = new Date(now + MAX_DEFERRAL_DAYS * 86_400_000)
		.toISOString()
		.slice(0, 10);
	const rows = [];
	const errors = [];
	let header = null;
	text.split("\n").forEach((raw, i) => {
		const line = raw.trim();
		if (!line.startsWith("|")) {
			header = null;
			return;
		}
		const cells = line
			.replace(/^\||\|$/g, "")
			.split("|")
			.map((c) => c.trim());
		if (header === null) {
			header = cells;
			return;
		}
		if (cells.every((c) => /^:?-+:?$/.test(c))) return;
		if (DEFERRAL_COLUMNS.some((c) => !header.includes(c))) return; // another table
		const row = Object.fromEntries(
			header.map((h, j) => [h, (cells[j] ?? "").replace(/`/g, "")]),
		);
		row.line = i + 1;
		const missing = DEFERRAL_COLUMNS.filter((c) => !row[c]);
		if (missing.length) {
			errors.push(
				`${file}:${i + 1}: deferral row is missing ${missing.join(", ")}`,
			);
		} else if (!isCalendarDate(row["Review-by"])) {
			errors.push(`${file}:${i + 1}: Review-by must be a date, YYYY-MM-DD`);
		} else if (row["Review-by"] > latestReview) {
			errors.push(
				`${file}:${i + 1}: Review-by must be at most ${MAX_DEFERRAL_DAYS} days ahead (${latestReview})`,
			);
		} else if (!/^(\d+\.x|\d+\.\d+\.\d+)$/.test(row["Held version"])) {
			errors.push(
				`${file}:${i + 1}: Held version must be an exact version or N.x`,
			);
		} else {
			rows.push(row);
		}
	});
	return { rows, errors };
}

/** The deferral that applies to a pin: same name, and the held exact version or major. */
export function deferralFor(deferrals, name, pinned) {
	return deferrals.find((d) => {
		if (d.Name !== name) return false;
		const held = /^(\d+)\.x$/.exec(d["Held version"]);
		if (held) return parsePin(pinned)?.major === Number(held[1]);
		return d["Held version"] === pinned;
	});
}

// ---------------------------------------------------------------------------------------------
// Report

/**
 * Compares each pin with its latest qualifying release. Returns one row per (kind, name, pinned):
 * `{ kind, name, pinned, latest, status, update, where[], note }`, status being
 * current, stale, deferred or error.
 */
export async function staleRows({
	pins,
	deferrals,
	ownVersions,
	fetchJson = httpFetchJson,
	now = Date.now(),
	concurrency = 8,
}) {
	const cutoff = now - MIN_RELEASE_AGE_MINUTES * 60_000;
	const today = new Date(now).toISOString().slice(0, 10);

	// One row per kind, name and pinned version; `where` lists every place it is pinned.
	const groups = new Map();
	for (const pin of pins) {
		const key = `${pin.kind}\0${pin.name}\0${pin.pinned}`;
		const group = groups.get(key) ?? { ...pin, where: [] };
		group.where.push(pin.where);
		groups.set(key, group);
	}

	// Releases are fetched once per source, however many pins share it.
	const releaseCache = new Map();
	const releasesOf = (pin) => {
		const key = `${pin.kind}\0${pin.name}`;
		if (!releaseCache.has(key)) {
			releaseCache.set(
				key,
				(async () => {
					if (pin.own) {
						// Our own package: the version in packages/*, which release.yml publishes. It
						// is on GitHub Packages, so the public registry is never asked.
						const version = ownVersions.get(pin.name);
						if (version === undefined)
							throw new Error("no package of this name in the workspace");
						return [{ version, date: new Date(0).toISOString() }];
					}
					if (pin.kind === "npm") return npmReleases(fetchJson, pin.name);
					if (pin.kind === "action") return githubReleases(fetchJson, pin.name);
					return SOURCES[pin.source.type](fetchJson, pin.source, today);
				})(),
			);
		}
		return releaseCache.get(key);
	};

	// The report gives the commit of a newer action release, as actions are pinned by SHA.
	const withCommit = async (row) => {
		if (row.kind !== "action" || !row.tag) return row;
		try {
			return { ...row, sha: await tagCommit(fetchJson, row.name, row.tag) };
		} catch {
			return row; // The version alone is still useful.
		}
	};

	const check = async (pin) => {
		const base = {
			kind: pin.kind,
			name: pin.name,
			pinned: pin.pinned,
			where: pin.where,
		};
		try {
			if (!parsePin(pin.pinned))
				return {
					...base,
					latest: "?",
					status: "error",
					note: "the pin is not a version",
				};
			const latest = newestQualifying(await releasesOf(pin), cutoff);
			if (latest === undefined)
				return {
					...base,
					latest: "?",
					status: "error",
					note: "no qualifying release found",
				};
			if (!isBehind(pin.pinned, latest.version))
				return { ...base, latest: latest.version, status: "current" };

			const row = {
				...base,
				latest: latest.version,
				update: updateType(pin.pinned, latest.version),
				tag: latest.tag,
			};
			const deferral = deferralFor(deferrals, pin.name, pin.pinned);
			if (deferral === undefined)
				return withCommit({ ...row, status: "stale" });
			if (deferral["Review-by"] < today)
				return withCommit({
					...row,
					status: "stale",
					note: `deferral expired on ${deferral["Review-by"]}`,
				});
			const held = /^(\d+)\.x$/.exec(deferral["Held version"]);
			if (held) {
				// A deferral that holds a major still expects the newest release within it.
				const inMajor = newestQualifying(
					await releasesOf(pin),
					cutoff,
					Number(held[1]),
				);
				// The pinned release itself is in that major, so finding none means the lookup failed.
				// For our own packages only the workspace version is known, not their release history.
				if (inMajor === undefined)
					return {
						...base,
						latest: "?",
						status: "error",
						note: pin.own
							? `only ${ownVersions.get(pin.name)} is known in the workspace; hold our own package at an exact version, not ${deferral["Held version"]}`
							: `no qualifying release found in ${deferral["Held version"]}`,
					};
				if (isBehind(pin.pinned, inMajor.version))
					return withCommit({
						...row,
						latest: inMajor.version,
						update: updateType(pin.pinned, inMajor.version),
						tag: inMajor.tag,
						status: "stale",
						note: `deferred to ${deferral["Held version"]}, but behind within it`,
					});
			}
			return {
				...row,
				status: "deferred",
				note: `deferred until ${deferral["Review-by"]}`,
			};
		} catch (error) {
			return { ...base, latest: "?", status: "error", note: error.message };
		}
	};

	const queue = [...groups.values()];
	const rows = [];
	await Promise.all(
		Array.from({ length: concurrency }, async () => {
			while (queue.length) rows.push(await check(queue.shift()));
		}),
	);

	const order = { npm: 0, action: 1, tool: 2 };
	return rows.sort(
		(a, b) =>
			order[a.kind] - order[b.kind] ||
			a.name.localeCompare(b.name) ||
			a.pinned.localeCompare(b.pinned),
	);
}

/** The Markdown report. `problems` are pins or deferral rows that could not be read. */
export function renderReport(rows, problems = []) {
	const by = (status) => rows.filter((r) => r.status === status);
	const stale = by("stale");
	const errors = by("error");
	const deferred = by("deferred");
	const where = (r) => r.where.map((w) => `\`${w}\``).join("<br>");
	const out = [];
	out.push(
		`${rows.length} pins checked: ${stale.length} stale, ${deferred.length} deferred, ${errors.length} failed, ${by("current").length} current.`,
		"",
		"A pin is stale when a newer stable release is at least 7 days old (ABIP-6). Update it by hand, in a PR with only that upgrade (`AGENTS.md`), or hold it back with a row in [`docs/version-deferrals.md`](../blob/main/docs/version-deferrals.md).",
		"",
	);
	if (stale.length) {
		out.push(
			"## Stale",
			"",
			"| Kind | Name | Pinned | Latest | Update | Where |",
			"|---|---|---|---|---|---|",
		);
		for (const r of stale) {
			const latest = r.sha ? `${r.latest} (\`${r.sha}\`)` : r.latest;
			const note = r.note ? ` (${r.note})` : "";
			out.push(
				`| ${r.kind} | \`${r.name}\` | ${r.pinned} | ${latest}${note} | ${r.update ?? "?"} | ${where(r)} |`,
			);
		}
		out.push("");
	}
	if (errors.length || problems.length) {
		out.push("## Could not check", "");
		for (const e of problems) out.push(`- ${e}`);
		for (const r of errors)
			out.push(`- ${r.kind} \`${r.name}\` ${r.pinned}: ${r.note}`);
		out.push("");
	}
	if (deferred.length) {
		out.push(
			"## Deferred",
			"",
			"| Kind | Name | Pinned | Latest | Note |",
			"|---|---|---|---|---|",
		);
		for (const r of deferred)
			out.push(
				`| ${r.kind} | \`${r.name}\` | ${r.pinned} | ${r.latest} | ${r.note} |`,
			);
		out.push("");
	}
	return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Repository access

const git = (...args) =>
	execFileSync("git", args, { cwd: ROOT, encoding: "utf8" })
		.split("\n")
		.filter(Boolean);
const read = (file) => readFileSync(resolve(ROOT, file), "utf8");
/** Tracked files containing a match of `regex`, outside vendored code. */
function grepFiles(regex) {
	try {
		return git(
			"grep",
			"-lE",
			regex,
			"--",
			".",
			":!vendor",
			":!packages/contracts/lib",
		);
	} catch (error) {
		if (error.status === 1) return []; // no match
		throw error;
	}
}

/** Every pin of this repository, with its kind, and the pins that could not be read. */
export function repositoryPins() {
	const parsed = manifests().map((file) => ({
		file,
		manifest: JSON.parse(read(file)),
	}));
	const own = new Set(parsed.map((m) => m.manifest.name).filter(Boolean));
	const ownVersions = new Map(
		parsed
			.filter((m) => /^packages\/[^/]+\/package\.json$/.test(m.file))
			.map((m) => [m.manifest.name, m.manifest.version]),
	);
	const pins = [];
	for (const pin of npmPins(parsed, own)) {
		// A pin on one of our packages is checked only where it is a released one (custom-example).
		if (pin.own && !ownVersions.has(pin.name)) continue;
		if (pin.own && !pin.where.startsWith("services/custom-example/")) continue;
		pins.push({ ...pin, kind: "npm" });
	}
	const problems = [];
	for (const file of git(
		"ls-files",
		".github/workflows/*.yml",
		".github/actions/**/action.yml",
	)) {
		const found = actionPins(read(file), file);
		for (const pin of found.pins) pins.push({ ...pin, kind: "action" });
		problems.push(...found.problems);
	}
	for (const tool of TOOLS) {
		let count = 0;
		const files = tool.grep
			? grepFiles(tool.grep)
			: git("ls-files", ...tool.files);
		for (const file of files) {
			const found = toolPins(tool, read(file), file);
			for (const pin of found.pins)
				pins.push({ ...pin, kind: "tool", source: tool.source });
			problems.push(...found.problems);
			count += found.pins.length;
		}
		if (count === 0)
			problems.push(
				`tool \`${tool.name}\`: no pin found in ${tool.files?.join(", ") ?? `files matching \`${tool.grep}\``} (update TOOLS in scripts/check-stale-pins.mjs)`,
			);
	}
	return { pins, ownVersions, problems };
}

async function main() {
	const { pins, ownVersions, problems } = repositoryPins();
	const { rows: deferrals, errors: deferralErrors } = parseDeferrals(
		read(DEFERRALS_FILE),
	);
	const rows = await staleRows({ pins, deferrals, ownVersions });
	const unchecked = [...problems, ...deferralErrors];
	console.log(renderReport(rows, unchecked));
	const bad = rows.some((r) => r.status === "stale" || r.status === "error");
	return bad || unchecked.length ? 1 : 0;
}

if (resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = await main();
}
