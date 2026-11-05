/**
 * Runs `pnpm coverage` and fails when the Solidity test coverage of `src/` drops below the
 * thresholds below.
 *
 * It reads the "Total" row of Foundry's summary table, the only report that has all four metrics
 * (`lcov.info` has no statement counts). The `coverage` script already leaves out tests, scripts,
 * dependencies and `src/testing/`, so the total covers the production contracts only.
 *
 * The thresholds are below 100% on purpose, except for functions. Coverage compiles with
 * `--ir-minimum` (GianoPaymaster is "stack too deep" without via-IR), and that source map loses
 * some lines the tests do run: assembly blocks, modifier bodies, and calls inside constructors and
 * initialisers. Raise a threshold when coverage rises; lower one only in a reviewed PR that says
 * why.
 *
 * Usage:  pnpm coverage:check
 */
import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

/** Minimum percentage per column of the summary table. */
const THRESHOLDS = {
	Lines: 95,
	Statements: 95,
	Branches: 95,
	Funcs: 100,
};

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const run = spawnSync("pnpm", ["coverage", "--report", "summary"], {
	cwd: root,
	encoding: "utf8",
	maxBuffer: 64 * 1024 * 1024,
	stdio: ["inherit", "pipe", "inherit"],
});
process.stdout.write(run.stdout ?? "");
if (run.status !== 0) {
	console.error(`\npnpm coverage failed (exit ${run.status ?? run.signal}).`);
	process.exit(1);
}

/** Splits a table row such as `| Total | 95.70% (467/488) | ... |` into its trimmed cells. */
const cells = (row) =>
	row
		.split("|")
		.slice(1, -1)
		.map((cell) => cell.trim());

const rows = run.stdout.split("\n").filter((row) => row.trim().startsWith("|"));
const header = rows.find((row) => row.includes("% Lines"));
const total = rows.find((row) => cells(row)[0] === "Total");
if (!header || !total) {
	console.error(
		"\nCould not find the coverage summary table in the forge output.",
	);
	process.exit(1);
}

const columns = cells(header).map((name) => name.replace("% ", ""));
const values = cells(total);

console.log();
let failed = false;
for (const [metric, threshold] of Object.entries(THRESHOLDS)) {
	const match = /\((\d+)\/(\d+)\)/.exec(values[columns.indexOf(metric)] ?? "");
	if (!match || Number(match[2]) === 0) {
		console.error(`FAIL ${metric}: no data in the summary table`);
		failed = true;
		continue;
	}
	const [hit, found] = [Number(match[1]), Number(match[2])];
	const percent = (hit / found) * 100;
	const ok = percent >= threshold;
	if (!ok) failed = true;
	console.log(
		`${ok ? "ok  " : "FAIL"} ${metric.padEnd(10)} ${percent.toFixed(2)}% (${hit}/${found}), minimum ${threshold}%`,
	);
}

if (failed) {
	console.error(
		"\nCoverage is below the threshold. Add tests for the new code, or see the comment in scripts/check-coverage.mjs.",
	);
	process.exit(1);
}
