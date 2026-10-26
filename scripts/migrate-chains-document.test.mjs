// node --test scripts/migrate-chains-document.test.mjs
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { migrate, migrateBundle } from "./migrate-chains-document.mjs";

const flat = {
	chainId: 84532,
	name: "Base Sepolia",
	rpcUrl: "https://base.example/KEY",
	bundlerUrl: "http://bundler-base-sepolia.giano-dev.local:4337",
	entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
	factory: "0x26dCd29390eba3B22BcCbd2143989E5994Ac7050",
	sponsorshipPaymaster: "0xf98b56de62ce88cEb70A9155582248cDBf2D0718",
	policy: { allowedPaymasters: ["0xf98b56de62ce88cEb70A9155582248cDBf2D0718"] },
	walletRpcUrl: "https://sepolia.base.org",
	refreshSeconds: 15,
};

describe("migrate-chains-document", () => {
	it("sorts every field into the shared top level or its service section", () => {
		const { document, notes } = migrate([flat]);
		assert.deepEqual(document, [
			{
				chainId: 84532,
				name: "Base Sepolia",
				rpcUrl: "https://base.example/KEY",
				entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
				sponsorshipPaymaster: "0xf98b56de62ce88cEb70A9155582248cDBf2D0718",
				walletApi: {
					factory: "0x26dCd29390eba3B22BcCbd2143989E5994Ac7050",
					policy: flat.policy,
				},
				paymasterAdmin: {
					walletRpcUrl: "https://sepolia.base.org",
					refreshSeconds: 15,
				},
			},
		]);
		assert.match(
			notes[0],
			/chain 84532.*dropped bundlerUrl "http:\/\/bundler-base-sepolia/,
		);
	});

	it("leaves out sections an entry has nothing for", () => {
		assert.deepEqual(
			migrate([{ chainId: 1, name: "A", rpcUrl: "http://a" }]).document,
			[{ chainId: 1, name: "A", rpcUrl: "http://a" }],
		);
	});

	it("refuses what it cannot place, and a document that is already migrated", () => {
		assert.throws(
			() => migrate([{ ...flat, mystery: 1 }]),
			/unrecognised field "mystery"/,
		);
		assert.throws(
			() => migrate([{ chainId: 1, walletApi: {} }]),
			/already has per-service sections/,
		);
		assert.throws(() => migrate({}), /must be a JSON array/);
	});

	it("converts chains inside the whole 1Password bundle, bumps its version, and leaves the rest alone", () => {
		const note = {
			"database-password": { value: "pw", version: 4 },
			chains: { value: JSON.stringify([flat]), version: 2 },
			"alto-executor-key": { value: "0xkey", version: 1 },
		};
		const { bundle, notes } = migrateBundle(note);
		assert.deepEqual(bundle["database-password"], note["database-password"]);
		assert.deepEqual(bundle["alto-executor-key"], note["alto-executor-key"]);
		assert.equal(bundle.chains.version, 3);
		assert.equal(typeof bundle.chains.value, "string");
		assert.deepEqual(JSON.parse(bundle.chains.value), migrate([flat]).document);
		assert.ok(notes.includes("chains.version 2 → 3"));
	});

	it("refuses a bundle without a usable chains entry", () => {
		assert.throws(
			() => migrateBundle({ chains: { value: [], version: 1 } }),
			/no "chains"/,
		);
		assert.throws(
			() => migrateBundle({ chains: { value: "[", version: 1 } }),
			/not valid JSON/,
		);
		assert.throws(() => migrateBundle([]), /must be a JSON object/);
	});
});
