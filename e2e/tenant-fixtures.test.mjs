// Keeps DAPP_ORIGINS in origins.mjs in step with TENANT_FIXTURES in deploy/docker-compose.e2e.yml.
// wallet-api reads the tenants' allowlists from TENANT_FIXTURES. The BYO wallet fixture and the
// tests read them from DAPP_ORIGINS. Compose cannot import origins.mjs, so this test links the two.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { DAPP_ORIGINS } from "./origins.mjs";

/** TENANT_FIXTURES, a JSON block scalar (`TENANT_FIXTURES: |`) in the compose file. */
function tenantFixtures() {
	const lines = readFileSync(
		new URL("../deploy/docker-compose.e2e.yml", import.meta.url),
		"utf8",
	).split("\n");
	const start = lines.findIndex((line) =>
		/^\s*TENANT_FIXTURES: \|\s*$/.test(line),
	);
	assert.notEqual(
		start,
		-1,
		"no `TENANT_FIXTURES: |` in docker-compose.e2e.yml",
	);
	const indent = lines[start].search(/\S/);
	const block = [];
	for (const line of lines.slice(start + 1)) {
		if (line.trim() !== "" && line.search(/\S/) <= indent) break;
		block.push(line);
	}
	return JSON.parse(block.join("\n"));
}

test("every tenant allows the dApps in DAPP_ORIGINS, and only those", () => {
	const fixtures = tenantFixtures();
	assert.deepEqual(
		fixtures.map((fixture) => fixture.slug).sort(),
		Object.keys(DAPP_ORIGINS).sort(),
	);
	for (const fixture of fixtures) {
		const expected = DAPP_ORIGINS[fixture.slug];
		assert.deepEqual(
			fixture.allowedDappOrigins,
			expected,
			`TENANT_FIXTURES ${fixture.slug}.allowedDappOrigins`,
		);
		assert.deepEqual(
			fixture.corsOrigins,
			expected,
			`TENANT_FIXTURES ${fixture.slug}.corsOrigins`,
		);
	}
});
