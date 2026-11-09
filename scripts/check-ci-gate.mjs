#!/usr/bin/env node
// CI gate check (openspec: ci-security-gates, design D12).
//
//   node scripts/check-ci-gate.mjs   check .github/workflows/ci.yml
//
// "CI passed" is the one required check for ci.yml. It passes only when every job it needs
// succeeded, so ci.yml must keep three properties:
//   - every other job is in the `needs` of ci-passed;
//   - ci-passed runs with `if: always()`, so a failed job fails it instead of skipping it (GitHub
//     counts a skipped required check as passed);
//   - no job or step has continue-on-error, which lets a failure count as success.
// The check parses the YAML with a full parser, so every key form (quoted, escaped, explicit `?`,
// tagged, anchored or merged) reads the same as GitHub reads it.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const CI_WORKFLOW = ".github/workflows/ci.yml";
export const GATE_JOB = "ci-passed";

const isObject = (v) =>
	v !== null && typeof v === "object" && !Array.isArray(v);

/** Every path in the parsed value whose key is continue-on-error, in any letter case. */
function continueOnErrorPaths(value, path = []) {
	if (Array.isArray(value))
		return value.flatMap((v, i) => continueOnErrorPaths(v, [...path, i]));
	if (!isObject(value)) return [];
	return Object.entries(value).flatMap(([k, v]) => [
		...(k.toLowerCase() === "continue-on-error"
			? [[...path, k].join(".")]
			: []),
		...continueOnErrorPaths(v, [...path, k]),
	]);
}

/** Returns a list of error messages for the text of ci.yml. Empty means it passes. */
export function checkCiGate(text) {
	const doc = parseDocument(text, { merge: true, uniqueKeys: true });
	const problems = [...doc.errors, ...doc.warnings];
	if (problems.length > 0)
		return problems.map(
			(e) => `${CI_WORKFLOW} is not valid YAML: ${e.message}`,
		);
	let workflow;
	try {
		workflow = doc.toJS({ maxAliasCount: 1000 });
	} catch (e) {
		return [`${CI_WORKFLOW} cannot be read: ${e.message}`];
	}
	if (!isObject(workflow) || !isObject(workflow.jobs))
		return [`${CI_WORKFLOW} has no jobs map`];

	const errors = continueOnErrorPaths(workflow).map(
		(p) =>
			`${p}: continue-on-error is not allowed in ${CI_WORKFLOW}. It lets a failure count as success.`,
	);
	const gate = workflow.jobs[GATE_JOB];
	if (!isObject(gate))
		return [...errors, `${CI_WORKFLOW} has no ${GATE_JOB} job`];

	if (gate.if !== "always()")
		errors.push(
			`${GATE_JOB} must have \`if: always()\`. Without it a failed job skips ${GATE_JOB}, and GitHub counts a skipped required check as passed.`,
		);

	const needs = typeof gate.needs === "string" ? [gate.needs] : gate.needs;
	if (!Array.isArray(needs) || needs.some((n) => typeof n !== "string"))
		return [...errors, `${GATE_JOB} needs must be a list of job names`];
	const jobs = Object.keys(workflow.jobs).filter((j) => j !== GATE_JOB);
	const missing = jobs.filter((j) => !needs.includes(j));
	const extra = needs.filter((n) => !jobs.includes(n));
	if (missing.length > 0)
		errors.push(`${GATE_JOB} needs is missing: ${missing.join(", ")}`);
	if (extra.length > 0)
		errors.push(
			`${GATE_JOB} needs names jobs that do not exist: ${extra.join(", ")}`,
		);
	return errors;
}

if (resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const errors = checkCiGate(readFileSync(join(ROOT, CI_WORKFLOW), "utf8"));
	for (const e of errors) console.error(e);
	if (errors.length > 0) process.exit(1);
	console.log(
		`${CI_WORKFLOW}: ${GATE_JOB} needs every job, and no job can fail silently.`,
	);
}
