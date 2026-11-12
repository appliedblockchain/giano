#!/usr/bin/env node
// CI gate check (openspec: ci-security-gates, design D12).
//
//   node scripts/check-ci-gate.mjs   check .github/workflows/ci.yml and every workflow's actions
//
// "CI passed" is the one required check for ci.yml. It passes only when every job it needs
// succeeded, so ci.yml must keep three properties:
//   - every other job is in the `needs` of ci-passed;
//   - ci-passed runs with `if: always()`, so a failed job fails it instead of skipping it (GitHub
//     counts a skipped required check as passed);
//   - no job or step has continue-on-error, which lets a failure count as success.
// Every workflow in .github/workflows must also pin each action and reusable workflow it uses to a
// full commit SHA, and each job container and service container image to a digest. A tag or a
// branch can be moved to other code; a commit SHA or a digest cannot. Local `./` paths come from the
// same commit as the workflow, so they need no pin, but the actions a local action uses are checked
// the same way.
// The check parses the YAML with a full parser, so every key form (quoted, escaped, explicit `?`,
// tagged, anchored or merged) reads the same as GitHub reads it.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const WORKFLOWS_DIR = ".github/workflows";
export const CI_WORKFLOW = `${WORKFLOWS_DIR}/ci.yml`;
export const GATE_JOB = "ci-passed";

// owner/repo[/path]@<commit SHA>, or a container image by digest.
const PINNED_ACTION = /^[^@\s]+@[0-9a-f]{40}$/;
const PINNED_IMAGE = /^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/;
// A job or service container image by digest. GitHub takes it without the docker:// prefix.
const PINNED_CONTAINER = /^[^@\s]+@sha256:[0-9a-f]{64}$/;

const isObject = (v) =>
	v !== null && typeof v === "object" && !Array.isArray(v);

/** Every [path, value] in the parsed value whose key is `name`, in any letter case. */
function keysNamed(name, value, path = []) {
	if (Array.isArray(value))
		return value.flatMap((v, i) => keysNamed(name, v, [...path, i]));
	if (!isObject(value)) return [];
	return Object.entries(value).flatMap(([k, v]) => [
		...(k.toLowerCase() === name ? [[[...path, k].join("."), v]] : []),
		...keysNamed(name, v, [...path, k]),
	]);
}

/** The parsed workflow, or the errors that stop it being read the way GitHub reads it. */
function parseWorkflow(text, file) {
	const doc = parseDocument(text, { merge: true, uniqueKeys: true });
	const problems = [...doc.errors, ...doc.warnings];
	if (problems.length > 0)
		return {
			errors: problems.map((e) => `${file} is not valid YAML: ${e.message}`),
		};
	try {
		return { workflow: doc.toJS({ maxAliasCount: 1000 }) };
	} catch (e) {
		return { errors: [`${file} cannot be read: ${e.message}`] };
	}
}

/** Returns a list of error messages for the text of ci.yml. Empty means it passes. */
export function checkCiGate(text) {
	const { workflow, errors: invalid } = parseWorkflow(text, CI_WORKFLOW);
	if (invalid) return invalid;
	if (!isObject(workflow) || !isObject(workflow.jobs))
		return [`${CI_WORKFLOW} has no jobs map`];

	const errors = keysNamed("continue-on-error", workflow).map(
		([p]) =>
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

/** The value of the key `name` in an object, in any letter case, as [key, value] pairs. */
const entriesNamed = (name, value) =>
	isObject(value)
		? Object.entries(value).filter(([k]) => k.toLowerCase() === name)
		: [];

/** Every [path, image] of a job container or service container in a parsed workflow. */
function containerImages(workflow) {
	return entriesNamed("jobs", workflow).flatMap(([jobsKey, jobs]) =>
		Object.entries(isObject(jobs) ? jobs : {}).flatMap(([id, job]) => {
			const at = `${jobsKey}.${id}`;
			// A container is an image string or a map with an `image` key.
			const containers = entriesNamed("container", job).flatMap(([k, c]) =>
				isObject(c)
					? entriesNamed("image", c).map(([ik, v]) => [`${at}.${k}.${ik}`, v])
					: [[`${at}.${k}`, c]],
			);
			const services = entriesNamed("services", job).flatMap(([k, map]) =>
				isObject(map)
					? Object.entries(map).flatMap(([name, svc]) =>
							isObject(svc)
								? entriesNamed("image", svc).map(([ik, v]) => [
										`${at}.${k}.${name}.${ik}`,
										v,
									])
								: [[`${at}.${k}.${name}`, svc]],
						)
					: [[`${at}.${k}`, map]],
			);
			return [...containers, ...services];
		}),
	);
}

/**
 * Returns an error for every `uses` in a workflow or action file that is not a local path or pinned
 * to a commit SHA, and for every job or service container image that is not pinned to a digest.
 */
export function checkActionPins(text, file) {
	const { workflow, errors } = parseWorkflow(text, file);
	if (errors) return errors;
	// Every key named `uses` at any depth, so a job, a step or a key form the check does not expect
	// cannot hide one. A `with:` input named `uses` is checked too, which fails closed.
	const actions = keysNamed("uses", workflow)
		.filter(
			([, v]) =>
				typeof v !== "string" ||
				!(v.startsWith("./") || PINNED_ACTION.test(v) || PINNED_IMAGE.test(v)),
		)
		.map(
			([p, v]) =>
				`${file}: ${p} is ${JSON.stringify(v)}. Pin it to a full 40-character commit SHA, with the release as a trailing comment, or use a local ./ path. A tag or a branch can be moved to other code.`,
		);
	// An expression such as ${{ matrix.image }} cannot be checked, so it fails closed.
	const images = containerImages(workflow)
		.filter(([, v]) => typeof v !== "string" || !PINNED_CONTAINER.test(v))
		.map(
			([p, v]) =>
				`${file}: ${p} is ${JSON.stringify(v)}. Pin the image to a digest (image@sha256:<64 hex>). A tag can be moved to another image.`,
		);
	return [...actions, ...images];
}

/** The local actions (`./` paths outside .github/workflows) that a workflow or action file uses. */
export function localActions(text, file) {
	const { workflow, errors } = parseWorkflow(text, file);
	if (errors) return [];
	return keysNamed("uses", workflow)
		.map(([, v]) => v)
		.filter(
			(v) =>
				typeof v === "string" &&
				v.startsWith("./") &&
				!v.startsWith(`./${WORKFLOWS_DIR}/`),
		)
		.map((v) => v.slice(2).replace(/\/+$/, ""));
}

/**
 * Checks the pins of every workflow, and of every local action they use, directly or through
 * another local action. A local action that has no action.yml or action.yaml fails.
 */
export function checkAllPins(root = ROOT) {
	const read = (file) => readFileSync(join(root, file), "utf8");
	const workflows = readdirSync(join(root, WORKFLOWS_DIR))
		.filter((f) => /\.ya?ml$/.test(f))
		.map((f) => `${WORKFLOWS_DIR}/${f}`);
	const errors = [];
	const seen = new Set();
	const queue = [];
	for (const file of workflows) {
		const text = read(file);
		errors.push(...checkActionPins(text, file));
		queue.push(...localActions(text, file));
	}
	while (queue.length > 0) {
		const dir = queue.shift();
		if (seen.has(dir)) continue;
		seen.add(dir);
		const file = ["action.yml", "action.yaml"]
			.map((f) => `${dir}/${f}`)
			.find((f) => existsSync(join(root, f)));
		if (!file) {
			errors.push(
				`./${dir} is used as a local action, but it has no action.yml or action.yaml`,
			);
			continue;
		}
		const text = read(file);
		errors.push(...checkActionPins(text, file));
		queue.push(...localActions(text, file));
	}
	return { errors, workflows: workflows.length, actions: seen.size };
}

if (
	process.argv[1] &&
	resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
	const pins = checkAllPins();
	const errors = [
		...checkCiGate(readFileSync(join(ROOT, CI_WORKFLOW), "utf8")),
		...pins.errors,
	];
	for (const e of errors) console.error(e);
	if (errors.length > 0) process.exit(1);
	console.log(
		`${CI_WORKFLOW}: ${GATE_JOB} needs every job, and no job can fail silently.`,
	);
	console.log(
		`${WORKFLOWS_DIR}: all ${pins.workflows} workflows and ${pins.actions} local actions pin every action to a commit SHA and every container image to a digest.`,
	);
}
