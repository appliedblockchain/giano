import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import {
	CI_WORKFLOW,
	checkActionPins,
	checkCiGate,
	WORKFLOWS_DIR,
} from "./check-ci-gate.mjs";

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

const SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1";
const DIGEST = `sha256:${"a".repeat(64)}`;
const steps = (...uses) =>
	`name: X\non: push\njobs:\n  build:\n    runs-on: ubuntu-26.04\n    steps:\n${uses.map((u) => `      - uses: ${u}\n`).join("")}`;

test("every real workflow pins its actions", () => {
	const files = readdirSync(WORKFLOWS_DIR).filter((f) => /\.ya?ml$/.test(f));
	assert.ok(files.includes("ci.yml"));
	for (const f of files) {
		const file = `${WORKFLOWS_DIR}/${f}`;
		assert.deepEqual(checkActionPins(readFileSync(file, "utf8"), file), []);
	}
});

test("actions pinned to a commit SHA, local paths and images by digest pass", () => {
	const text = steps(
		`actions/checkout@${SHA} # v7.0.1`,
		`github/codeql-action/init@${SHA}`,
		"./.github/actions/setup",
		`docker://alpine@${DIGEST}`,
	);
	assert.deepEqual(checkActionPins(text, "x.yml"), []);
	const reusable = `on: push\njobs:\n  ci:\n    uses: ./.github/workflows/ci.yml\n  other:\n    uses: org/repo/.github/workflows/w.yml@${SHA}\n`;
	assert.deepEqual(checkActionPins(reusable, "x.yml"), []);
});

test("an action on a tag, a branch, a short SHA or an image tag fails", () => {
	for (const uses of [
		"actions/checkout@v7",
		"actions/checkout@v7.0.1",
		"actions/checkout@main",
		"actions/checkout",
		`actions/checkout@${SHA.slice(0, 7)}`,
		`actions/checkout@${SHA.toUpperCase()}`,
		`actions/checkout@${SHA}0`,
		"docker://alpine:3.20",
		`docker://alpine@sha256:${"a".repeat(63)}`,
		'"actions/checkout@v7"',
	]) {
		const errors = checkActionPins(steps(uses), "x.yml");
		assert.equal(errors.length, 1, uses);
		assert.match(errors[0], /^x\.yml: jobs\.build\.steps\.0\.uses is /);
	}
	const reusable =
		"on: push\njobs:\n  other:\n    uses: org/repo/.github/workflows/w.yml@main\n";
	assert.match(checkActionPins(reusable, "x.yml")[0], /jobs\.other\.uses/);
});

test("an unpinned action fails in every key form", () => {
	for (const key of [
		"uses",
		'"uses"',
		"'uses'",
		'"u\\x73es"',
		"Uses",
		"? uses\n       ",
	]) {
		const text = `on: push\njobs:\n  build:\n    steps:\n      - ${key}: actions/checkout@v7\n`;
		assert.equal(checkActionPins(text, "x.yml").length, 1, key);
	}
	const anchored = `on: push\nx: &a { uses: actions/checkout@v7 }\njobs:\n  build:\n    steps:\n      - <<: *a\n`;
	assert.equal(checkActionPins(anchored, "x.yml").length, 2);
	assert.match(
		checkActionPins(steps("[actions/checkout]"), "x.yml")[0],
		/is \["actions\/checkout"\]/,
	);
	assert.match(
		checkActionPins(`${steps("x")}  build:\n`, "x.yml")[0],
		/not valid YAML/,
	);
});
