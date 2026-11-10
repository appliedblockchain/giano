import assert from "node:assert/strict";
import { test } from "node:test";
import { driftLines, driftUrl } from "../scripts/doctor-drift";

const now = Date.parse("2026-11-10T12:00:00Z");
const chain = (overrides: object = {}) => ({
	chainId: 84532,
	checkedAt: "2026-11-10T11:59:00Z",
	entries: [],
	unchecked: [],
	...overrides,
});
const levels = (lines: ReturnType<typeof driftLines>) =>
	lines.map((line) => `${line.level} ${line.label}`);

test("drift URL keeps the base path, and refuses http except on this machine", () => {
	assert.equal(
		driftUrl("https://ops.example/api").toString(),
		"https://ops.example/api/v1/platform/drift",
	);
	assert.equal(
		driftUrl("https://ops.example/").toString(),
		"https://ops.example/v1/platform/drift",
	);
	assert.equal(
		driftUrl("http://localhost:8080").toString(),
		"http://localhost:8080/v1/platform/drift",
	);
	assert.throws(() => driftUrl("http://ops.example"), /must be https/);
});

test("no drift only when every tenant was compared", () => {
	assert.deepEqual(levels(driftLines(chain(), now)), ["ok no drift"]);
	assert.deepEqual(levels(driftLines(chain({ unchecked: ["t1"] }), now)), [
		"warn drift: not compared",
	]);
});

test("another deployment's tenant on a shared paymaster warns; this deployment's drift fails", () => {
	const unknown = { kind: "unknown-tenant", tenantId: "t1" };
	assert.deepEqual(levels(driftLines(chain({ entries: [unknown] }), now)), [
		"warn drift: unknown-tenant",
		"ok no drift",
	]);
	assert.deepEqual(
		levels(
			driftLines(
				chain({
					entries: [unknown, { kind: "enabled-state", tenantId: "t2" }],
				}),
				now,
			),
		),
		["warn drift: unknown-tenant", "fail drift: enabled-state"],
	);
});

test("an old result warns, and a chain wallet-api could not compute fails", () => {
	assert.deepEqual(
		levels(driftLines(chain({ checkedAt: "2026-11-09T12:00:00Z" }), now)),
		["warn drift result is old", "ok no drift"],
	);
	assert.deepEqual(
		levels(
			driftLines(
				{ chainId: 84532, error: "drift-unavailable", message: "unreadable" },
				now,
			),
		),
		["fail read the drift"],
	);
});
