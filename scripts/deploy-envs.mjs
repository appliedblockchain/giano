#!/usr/bin/env node
// Which environments a deploy.yml run may roll (ABIP-1, openspec: production-release-branch).
//
//   EVENT=push REF=refs/heads/main BEFORE=before.json AFTER=infra/versions.json node scripts/deploy-envs.mjs
//   EVENT=workflow_dispatch REF=refs/heads/production INPUT_ENVIRONMENT=prd node scripts/deploy-envs.mjs
//
// Prints a JSON array of environment names on stdout, and GitHub `::notice::` / `::error::` lines on
// stderr. Exits 1 when a dispatch asks for an environment the branch may not deploy.
//
// prd deploys only from the protected `production` branch; dev and stg only from `main`. A push is
// rolled for every environment whose declared tag changed AND that its branch may deploy. A change
// to another environment's key is ignored with a notice, so bumping .prd on main is the first half
// of a promotion, not a deploy. No dependencies.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ENVIRONMENTS = ["dev", "stg", "prd"];
export const DEPLOYS_FROM = { dev: "main", stg: "main", prd: "production" };

const branchOf = (ref) => ref.replace(/^refs\/heads\//, "");
const allowedOn = (ref) =>
	ENVIRONMENTS.filter((e) => DEPLOYS_FROM[e] === branchOf(ref));

/**
 * @returns {{ envs: string[], notices: string[], error?: string }}
 */
export function plan({ event, ref, before = {}, after = {}, input }) {
	const allowed = allowedOn(ref);
	if (event === "workflow_dispatch") {
		if (!allowed.includes(input)) {
			return {
				envs: [],
				notices: [],
				error: `${input} deploys only from the ${DEPLOYS_FROM[input] ?? "?"} branch; this run is on ${branchOf(ref)}`,
			};
		}
		return { envs: [input], notices: [] };
	}
	const changed = ENVIRONMENTS.filter(
		(e) => (before[e] ?? "") !== (after[e] ?? ""),
	);
	const notices = changed
		.filter((e) => !allowed.includes(e))
		.map(
			(e) =>
				`${e}'s declared tag changed on ${branchOf(ref)}, but ${e} deploys only from ${DEPLOYS_FROM[e]}; not deploying it here`,
		);
	return { envs: changed.filter((e) => allowed.includes(e)), notices };
}

function readJson(file) {
	try {
		return JSON.parse(readFileSync(file, "utf8"));
	} catch {
		return {};
	}
}

if (resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const env = process.env;
	const result = plan({
		event: env.EVENT,
		ref: env.REF,
		before: env.BEFORE ? readJson(env.BEFORE) : {},
		after: env.AFTER ? readJson(env.AFTER) : {},
		input: env.INPUT_ENVIRONMENT,
	});
	for (const n of result.notices) console.error(`::notice::${n}`);
	if (result.error) {
		console.error(`::error::${result.error}`);
		process.exitCode = 1;
	} else {
		console.log(JSON.stringify(result.envs));
	}
}
