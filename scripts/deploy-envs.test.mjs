import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { plan } from "./deploy-envs.mjs";

const A = "a".repeat(40);
const B = "b".repeat(40);
const MAIN = "refs/heads/main";
const PRODUCTION = "refs/heads/production";

describe("deploy-envs: pushes", () => {
	it("rolls dev from main", () => {
		assert.deepEqual(
			plan({ event: "push", ref: MAIN, before: { dev: A }, after: { dev: B } })
				.envs,
			["dev"],
		);
	});

	it("rolls stg from main", () => {
		assert.deepEqual(
			plan({ event: "push", ref: MAIN, before: { stg: "" }, after: { stg: B } })
				.envs,
			["stg"],
		);
	});

	it("does not roll prd from main, and says why", () => {
		const r = plan({
			event: "push",
			ref: MAIN,
			before: { prd: "" },
			after: { prd: B },
		});
		assert.deepEqual(r.envs, []);
		assert.equal(r.notices.length, 1);
		assert.match(r.notices[0], /prd deploys only from production/);
	});

	it("rolls prd from production", () => {
		assert.deepEqual(
			plan({
				event: "push",
				ref: PRODUCTION,
				before: { prd: A },
				after: { prd: B },
			}).envs,
			["prd"],
		);
	});

	it("does not roll dev or stg from production", () => {
		const r = plan({
			event: "push",
			ref: PRODUCTION,
			before: { dev: A, stg: A, prd: A },
			after: { dev: B, stg: B, prd: B },
		});
		assert.deepEqual(r.envs, ["prd"]);
		assert.equal(r.notices.length, 2);
	});

	it("rolls nothing for a formatting-only change", () => {
		const r = plan({
			event: "push",
			ref: MAIN,
			before: { dev: A, stg: "", prd: "" },
			after: { dev: A, stg: "", prd: "" },
		});
		assert.deepEqual(r, { envs: [], notices: [] });
	});

	it("deploys nothing from any other branch", () => {
		assert.deepEqual(
			plan({
				event: "push",
				ref: "refs/heads/feat/x",
				before: { dev: A },
				after: { dev: B },
			}).envs,
			[],
		);
	});
});

describe("deploy-envs: dispatches", () => {
	it("re-rolls prd from production", () => {
		assert.deepEqual(
			plan({ event: "workflow_dispatch", ref: PRODUCTION, input: "prd" }).envs,
			["prd"],
		);
	});

	it("refuses a prd dispatch from main", () => {
		const r = plan({ event: "workflow_dispatch", ref: MAIN, input: "prd" });
		assert.deepEqual(r.envs, []);
		assert.match(
			r.error,
			/prd deploys only from the production branch; this run is on main/,
		);
	});

	it("refuses a dev dispatch from production", () => {
		assert.match(
			plan({ event: "workflow_dispatch", ref: PRODUCTION, input: "dev" }).error,
			/dev deploys only from the main branch/,
		);
	});

	it("re-rolls dev from main", () => {
		assert.deepEqual(
			plan({ event: "workflow_dispatch", ref: MAIN, input: "dev" }).envs,
			["dev"],
		);
	});
});
