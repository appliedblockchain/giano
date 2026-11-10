/** deploy/records.ts: the record's deployer is unknown until a signing run writes it. */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readRecord, recordPath, writeRecord } from "./records";

const LOCAL = "0x000000000000000000000000000000000000dEaD";
const OTHER = "0x1000000000000000000000000000000000000001";

test("a record no signer wrote has no deployer, and any signer may extend it", () => {
	const dir = mkdtempSync(join(tmpdir(), "records-"));
	try {
		// A keyless run (or the verify-only Helm Job on a fresh volume) reads and saves the record.
		const keyless = readRecord(31337, undefined, dir);
		assert.equal(keyless.deployer, null);
		writeRecord(keyless, dir);
		// deploy-local.ts then reads it for the local deployer: no "written for deployer 0x0…" refusal.
		assert.equal(readRecord(31337, LOCAL, dir).deployer, null);
		// Once a signer is recorded, another one is still refused.
		writeRecord({ ...keyless, deployer: LOCAL }, dir);
		assert.throws(() => readRecord(31337, OTHER, dir), /written for deployer/);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("a record written with the zero address as deployer reads as no deployer", () => {
	const dir = mkdtempSync(join(tmpdir(), "records-"));
	try {
		writeFileSync(
			recordPath(31337, dir),
			JSON.stringify({
				chainId: 31337,
				deployer: `0x${"0".repeat(40)}`,
				contracts: {},
				upgrades: [],
			}),
		);
		assert.equal(readRecord(31337, LOCAL, dir).deployer, null);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
