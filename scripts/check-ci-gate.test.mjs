import assert from "node:assert/strict";
import {
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import {
	CI_WORKFLOW,
	checkActionPins,
	checkAllPins,
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

const IMAGE = `node@${DIGEST}`;
const job = (body) =>
	`on: push\njobs:\n  build:\n    runs-on: ubuntu-26.04\n${body}    steps:\n      - run: make\n`;

test("job and service container images pinned to a digest pass", () => {
	for (const body of [
		`    container: ${IMAGE}\n`,
		`    container:\n      image: ${IMAGE}\n      options: --cpus 1\n`,
		`    services:\n      db:\n        image: ${IMAGE}\n`,
	])
		assert.deepEqual(checkActionPins(job(body), "x.yml"), [], body);
});

test("a container or service image on a tag, without a digest or from an expression fails", () => {
	for (const [body, path] of [
		["    container: node:24\n", "jobs.build.container"],
		["    container:\n      image: node:24\n", "jobs.build.container.image"],
		["    Container:\n      Image: node\n", "jobs.build.Container.Image"],
		[
			"    services:\n      db:\n        image: postgres:17\n",
			"jobs.build.services.db.image",
		],
		["    services:\n      db: postgres:17\n", "jobs.build.services.db"],
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, not a template
		["    container: ${{ matrix.image }}\n", "jobs.build.container"],
	]) {
		const errors = checkActionPins(job(body), "x.yml");
		assert.equal(errors.length, 1, body);
		assert.match(
			errors[0],
			new RegExp(
				`^x\\.yml: ${path.replaceAll(".", "\\.")} is .*Pin the image to a digest`,
			),
		);
	}
});

test("an image input of a step is not a container image", () => {
	const text = `${steps(`aws-actions/amazon-ecs-render-task-definition@${SHA}`)}        with:\n          image: repo/app:latest\n`;
	assert.deepEqual(checkActionPins(text, "x.yml"), []);
});

const repo = (files) => {
	const root = mkdtempSync(join(tmpdir(), "ci-gate-"));
	for (const [file, text] of Object.entries(files)) {
		mkdirSync(dirname(join(root, file)), { recursive: true });
		writeFileSync(join(root, file), text);
	}
	return root;
};

test("the actions a local action uses are checked, also through another local action", () => {
	const root = repo({
		[`${WORKFLOWS_DIR}/w.yml`]: steps(
			"./.github/actions/setup",
			"./.github/workflows/r.yml",
		),
		[`${WORKFLOWS_DIR}/r.yml`]: steps(`actions/checkout@${SHA}`),
		".github/actions/setup/action.yml": `runs:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v6\n    - uses: ./.github/actions/inner\n`,
		".github/actions/inner/action.yaml": `runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v5\n    - uses: ./.github/actions/setup\n`,
	});
	const { errors, workflows, actions } = checkAllPins(root);
	assert.equal(workflows, 2);
	assert.equal(actions, 2);
	assert.equal(errors.length, 2);
	assert.match(
		errors[0],
		/^\.github\/actions\/setup\/action\.yml: runs\.steps\.0\.uses is "actions\/setup-node@v6"/,
	);
	assert.match(
		errors[1],
		/^\.github\/actions\/inner\/action\.yaml: runs\.steps\.0\.uses is "actions\/cache@v5"/,
	);
});

test("a local action without an action file fails", () => {
	const root = repo({
		[`${WORKFLOWS_DIR}/w.yml`]: steps("./.github/actions/missing"),
	});
	assert.deepEqual(checkAllPins(root).errors, [
		"./.github/actions/missing is used as a local action, but it has no action.yml or action.yaml",
	]);
});

test("a local Docker action passes only with a docker:// image pinned to a digest", () => {
	const docker = (image) =>
		repo({
			[`${WORKFLOWS_DIR}/w.yml`]: steps("./.github/actions/d"),
			".github/actions/d/action.yml": `runs:\n  using: docker\n  image: ${image}\n`,
			".github/actions/d/Dockerfile": "FROM alpine:3.20\n",
		});
	assert.deepEqual(
		checkAllPins(docker(`docker://alpine@${DIGEST}`)).errors,
		[],
	);
	for (const image of [
		"docker://alpine:3.20",
		"docker://alpine",
		`alpine@${DIGEST}`,
		"Dockerfile",
		`'\${{ inputs.image }}'`,
		"[docker://alpine]",
	]) {
		const { errors } = checkAllPins(docker(image));
		assert.equal(errors.length, 1, image);
		assert.match(
			errors[0],
			/^\.github\/actions\/d\/action\.yml: runs\.image is .*not a tag or a Dockerfile/,
		);
	}
	const upper = repo({
		[`${WORKFLOWS_DIR}/w.yml`]: steps("./.github/actions/d"),
		".github/actions/d/action.yml":
			"Runs:\n  using: docker\n  Image: docker://alpine:3.20\n",
	});
	assert.match(checkAllPins(upper).errors[0], /Runs\.Image is/);
});

test("a local action in a folder of .github/workflows, or reached through .., is checked", () => {
	const action = `runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v5\n`;
	for (const uses of [
		"./.github/workflows/helper",
		"./.github/workflows/helper/",
		"./.github/workflows/../workflows/helper",
		"./.github/workflows/../actions/../workflows/helper",
	]) {
		const root = repo({
			[`${WORKFLOWS_DIR}/w.yml`]: steps(uses),
			".github/workflows/helper/action.yml": action,
		});
		const { errors, actions } = checkAllPins(root);
		assert.equal(actions, 1, uses);
		assert.equal(errors.length, 1, uses);
		assert.match(
			errors[0],
			/^\.github\/workflows\/helper\/action\.yml: runs\.steps\.0\.uses is "actions\/cache@v5"/,
		);
	}
	const reusable = repo({
		[`${WORKFLOWS_DIR}/w.yml`]: steps(
			"./.github/workflows/r.yml",
			"./.github/actions/../workflows/r.yml",
		),
		[`${WORKFLOWS_DIR}/r.yml`]: steps(`actions/checkout@${SHA}`),
	});
	assert.deepEqual(checkAllPins(reusable), {
		errors: [],
		workflows: 2,
		actions: 0,
	});
	const outside = repo({
		[`${WORKFLOWS_DIR}/w.yml`]: steps("./../other/action"),
	});
	assert.deepEqual(checkAllPins(outside).errors, [
		"./../other/action is used as a local action, but it is outside the repository",
	]);
});

test("the real workflows and their local actions pass", () => {
	assert.deepEqual(checkAllPins().errors, []);
});
