import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CI_WORKFLOW, checkCiGate } from "./check-ci-gate.mjs";

const workflow = (
	jobs,
	gate = "    if: always()\n    needs: [build, test]\n",
) =>
	`name: CI\non: pull_request\njobs:\n${jobs}  ci-passed:\n${gate}    runs-on: ubuntu-26.04\n    steps:\n      - run: "true"\n`;
const JOBS =
	"  build:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: make\n  test:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: make test\n";

test("the real ci.yml passes", () => {
	assert.deepEqual(checkCiGate(readFileSync(CI_WORKFLOW, "utf8")), []);
});

test("a workflow whose gate needs every job passes", () => {
	assert.deepEqual(checkCiGate(workflow(JOBS)), []);
	assert.deepEqual(
		checkCiGate(
			workflow(
				JOBS,
				"    if: always()\n    needs:\n      - build\n      - test\n",
			),
		),
		[],
	);
});

test("a job missing from needs fails, in any key form", () => {
	for (const key of [
		"deploy",
		'"deploy"',
		"'deploy'",
		'"dep\\x6Coy"',
		"? deploy\n  ",
	]) {
		const jobs = `${JOBS}  ${key}:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: make\n`;
		assert.deepEqual(
			checkCiGate(workflow(jobs)),
			["ci-passed needs is missing: deploy"],
			key,
		);
	}
});

test("a needs entry that is not a job fails", () => {
	assert.deepEqual(
		checkCiGate(
			workflow(JOBS, "    if: always()\n    needs: [build, test, lint]\n"),
		),
		["ci-passed needs names jobs that do not exist: lint"],
	);
});

test("continue-on-error fails in every key form and place", () => {
	const forms = [
		"      - run: make\n        continue-on-error: true\n",
		'      - run: make\n        "continue-on-error": true\n',
		'      - run: make\n        "continue\\x2Don-error": true\n',
		"      - run: make\n        ? continue-on-error\n        : true\n",
		"      - run: make\n        !!str continue-on-error: true\n",
		"      - &x continue-on-error: true\n        run: make\n",
		"      - { run: make, continue-on-error: true }\n",
		"      - run: make\n        Continue-On-Error: true\n",
	];
	for (const step of forms) {
		const jobs = `  build:\n    runs-on: ubuntu-26.04\n    steps:\n${step}  test:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: make test\n`;
		const errors = checkCiGate(workflow(jobs));
		assert.equal(errors.length, 1, step);
		assert.match(errors[0], /continue-on-error is not allowed/, step);
	}
});

test("continue-on-error brought in by a merge key fails", () => {
	const text = `x-defaults: &defaults\n  continue-on-error: true\n${workflow(
		"  build:\n    <<: *defaults\n    runs-on: ubuntu-26.04\n    steps:\n      - run: make\n  test:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: make test\n",
	)}`;
	const errors = checkCiGate(text);
	assert.ok(
		errors.some((e) => e.startsWith("jobs.build.continue-on-error:")),
		errors.join("\n"),
	);
});

test("a gate without if: always() fails", () => {
	for (const gate of [
		"    needs: [build, test]\n",
		"    if: success()\n    needs: [build, test]\n",
		"    if: always() && false\n    needs: [build, test]\n",
	]) {
		const errors = checkCiGate(workflow(JOBS, gate));
		assert.equal(errors.length, 1, gate);
		assert.match(errors[0], /must have `if: always\(\)`/);
	}
});

test("duplicate keys, unknown tags and a missing gate fail", () => {
	assert.match(
		checkCiGate(workflow(`${JOBS}  build:\n    runs-on: x\n`))[0],
		/not valid YAML/,
	);
	assert.match(
		checkCiGate(
			workflow(JOBS).replace("run: make\n", "run: !custom make\n"),
		)[0],
		/not valid YAML/,
	);
	assert.deepEqual(checkCiGate(`jobs:\n${JOBS}`), [
		`${CI_WORKFLOW} has no ci-passed job`,
	]);
	assert.deepEqual(checkCiGate("name: CI\n"), [
		`${CI_WORKFLOW} has no jobs map`,
	]);
});
