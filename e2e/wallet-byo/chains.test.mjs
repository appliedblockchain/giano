// node --test e2e/wallet-byo/chains.test.mjs
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ChainsConfigError, resolveChains } from "./chains.mjs";

/** The part of ../devnet/addresses.json that resolveChains reads. */
const DEVNET = { chainId: 31337 };

/** Asserts a refusal whose message contains every one of `names`. */
function refuses(env, devnet, ...names) {
	assert.throws(
		() => resolveChains(env, devnet),
		(error) => {
			assert.ok(error instanceof ChainsConfigError, String(error));
			for (const name of names) assert.match(error.message, new RegExp(name));
			return true;
		},
	);
}

describe("CHAINS", () => {
	it("serves every chain in the list, in order", () => {
		const chains = [
			{ chainId: 31337, name: "Devnet A" },
			{ chainId: 31338, name: "Devnet B" },
			{ chainId: 31339, name: "Devnet SD (Silent Data)" },
		];
		assert.deepEqual(
			resolveChains({ CHAINS: JSON.stringify(chains) }, null),
			chains,
		);
	});

	it("wins over the devnet default", () => {
		assert.deepEqual(
			resolveChains(
				{ CHAINS: '[{"chainId":84532,"name":"Base Sepolia"}]' },
				DEVNET,
			),
			[{ chainId: 84532, name: "Base Sepolia" }],
		);
	});

	it("drops keys other than chainId and name", () => {
		assert.deepEqual(
			resolveChains(
				{ CHAINS: '[{"chainId":84532,"name":"Base Sepolia","rpcUrl":"x"}]' },
				null,
			),
			[{ chainId: 84532, name: "Base Sepolia" }],
		);
	});

	it("is ignored when empty, so the pair applies", () => {
		assert.deepEqual(resolveChains({ CHAINS: "", CHAIN_ID: "84532" }, null), [
			{ chainId: 84532, name: "chain 84532" },
		]);
	});

	it("refuses an empty list", () => {
		refuses({ CHAINS: "[]" }, DEVNET, "CHAINS", "empty");
	});

	it("refuses JSON that is not an array of objects", () => {
		refuses({ CHAINS: "not json" }, null, "CHAINS", "JSON");
		refuses({ CHAINS: '{"chainId":1,"name":"x"}' }, null, "CHAINS", "array");
		refuses({ CHAINS: "[1]" }, null, "CHAINS\\[0\\]", "object");
	});

	it("refuses an id that is not a positive integer", () => {
		for (const chainId of [0, -1, 1.5, "84532", null, 2 ** 53]) {
			refuses(
				{ CHAINS: JSON.stringify([{ chainId, name: "x" }]) },
				null,
				"CHAINS\\[0\\]\\.chainId",
				"positive integer",
			);
		}
	});

	it("refuses a repeated id", () => {
		refuses(
			{
				CHAINS: JSON.stringify([
					{ chainId: 1, name: "a" },
					{ chainId: 1, name: "b" },
				]),
			},
			null,
			"Chain 1 appears twice",
			"CHAINS\\[1\\]",
		);
	});

	it("refuses an empty or missing name", () => {
		refuses(
			{ CHAINS: '[{"chainId":1,"name":"  "}]' },
			null,
			"CHAINS\\[0\\]\\.name",
		);
		refuses({ CHAINS: '[{"chainId":1}]' }, null, "CHAINS\\[0\\]\\.name");
	});

	it("refuses CHAINS set together with CHAIN_ID", () => {
		refuses(
			{ CHAINS: '[{"chainId":1,"name":"a"}]', CHAIN_ID: "1" },
			null,
			"CHAINS",
			"CHAIN_ID",
		);
	});

	it("refuses CHAINS set together with CHAIN_B_ID", () => {
		refuses(
			{ CHAINS: '[{"chainId":1,"name":"a"}]', CHAIN_B_ID: "2" },
			null,
			"CHAINS",
			"CHAIN_B_ID",
		);
	});

	it("refuses CHAINS with both, and names all three variables", () => {
		refuses(
			{ CHAINS: '[{"chainId":1,"name":"a"}]', CHAIN_ID: "1", CHAIN_B_ID: "2" },
			DEVNET,
			"CHAINS",
			"CHAIN_ID",
			"CHAIN_B_ID",
		);
	});

	it("refuses CHAINS set together with a leftover name", () => {
		for (const name of ["CHAIN_NAME", "CHAIN_B_NAME"]) {
			refuses(
				{ CHAINS: '[{"chainId":1,"name":"a"}]', [name]: "Base Sepolia" },
				null,
				"CHAINS is set together with",
				name,
			);
		}
	});

	it("refuses CHAINS set together with CHAIN_B_ID=0, which CHAINS would ignore", () => {
		refuses(
			{ CHAINS: '[{"chainId":1,"name":"a"}]', CHAIN_B_ID: "0" },
			null,
			"CHAINS is set together with CHAIN_B_ID",
		);
	});
});

describe("the CHAIN_ID / CHAIN_B_ID pair", () => {
	it("serves two named chains", () => {
		assert.deepEqual(
			resolveChains(
				{
					CHAIN_ID: "84532",
					CHAIN_NAME: "Base Sepolia",
					CHAIN_B_ID: "11155111",
					CHAIN_B_NAME: "Ethereum Sepolia",
				},
				null,
			),
			[
				{ chainId: 84532, name: "Base Sepolia" },
				{ chainId: 11155111, name: "Ethereum Sepolia" },
			],
		);
	});

	it("names an unnamed chain 'chain <id>' outside a devnet checkout (the AWS dev environment)", () => {
		assert.deepEqual(
			resolveChains({ CHAIN_ID: "84532", CHAIN_B_ID: "11155111" }, null),
			[
				{ chainId: 84532, name: "chain 84532" },
				{ chainId: 11155111, name: "chain 11155111" },
			],
		);
	});

	it("serves one chain when CHAIN_B_ID is unset, empty or 0", () => {
		for (const CHAIN_B_ID of [undefined, "", "0", " ", "0\n"]) {
			assert.deepEqual(resolveChains({ CHAIN_ID: "84532", CHAIN_B_ID }, null), [
				{ chainId: 84532, name: "chain 84532" },
			]);
		}
	});

	it("ignores spaces and a newline around an id (an env file or a secret)", () => {
		assert.deepEqual(
			resolveChains({ CHAIN_ID: " 84532\n", CHAIN_B_ID: "11155111 " }, null),
			[
				{ chainId: 84532, name: "chain 84532" },
				{ chainId: 11155111, name: "chain 11155111" },
			],
		);
	});

	it("requires CHAIN_ID outside a devnet checkout, and names CHAINS as the other form", () => {
		refuses({}, null, "CHAIN_ID is required", "CHAINS");
		refuses({ CHAIN_ID: "" }, null, "CHAIN_ID is required");
		refuses({ CHAIN_B_ID: "2" }, null, "CHAIN_ID is required");
	});

	it("refuses an id that is not a positive integer", () => {
		refuses({ CHAIN_ID: "abc" }, null, "CHAIN_ID", "positive integer");
		refuses({ CHAIN_ID: "-5" }, null, "CHAIN_ID", "positive integer");
		refuses(
			{ CHAIN_ID: "1", CHAIN_B_ID: "1.5" },
			null,
			"CHAIN_B_ID",
			"positive integer",
		);
	});

	it("refuses ids that serve.mjs used to pass to Number() without a word", () => {
		// Hex: Number() read it as 84532.
		refuses({ CHAIN_ID: "0x14a34" }, null, "CHAIN_ID", "positive integer");
		// These used to drop the second chain. Now they stop the service.
		for (const CHAIN_B_ID of ["00", "-1"]) {
			refuses(
				{ CHAIN_ID: "84532", CHAIN_B_ID },
				null,
				"CHAIN_B_ID",
				"positive integer",
			);
		}
	});

	it("refuses the same id twice", () => {
		refuses(
			{ CHAIN_ID: "84532", CHAIN_B_ID: "84532" },
			null,
			"Chain 84532 appears twice",
			"CHAIN_B_ID",
		);
	});

	it("refuses an empty name", () => {
		refuses({ CHAIN_ID: "1", CHAIN_NAME: "" }, null, "CHAIN_NAME");
		refuses(
			{ CHAIN_ID: "1", CHAIN_B_ID: "2", CHAIN_B_NAME: " " },
			null,
			"CHAIN_B_NAME",
		);
	});
});

describe("devnet checkout", () => {
	it("defaults to every local chain with no chain variable", () => {
		assert.deepEqual(resolveChains({}, DEVNET), [
			{ chainId: 31337, name: "Devnet A" },
			{ chainId: 31338, name: "Devnet B" },
			{ chainId: 31339, name: "Devnet SD (Silent Data)" },
		]);
	});

	it("defaults to every local chain when CHAINS is empty", () => {
		assert.equal(resolveChains({ CHAINS: "" }, DEVNET).length, 3);
	});

	it("uses the pair, not the default, when any pair variable is set", () => {
		assert.deepEqual(resolveChains({ CHAIN_ID: "31337" }, DEVNET), [
			{ chainId: 31337, name: "Devnet A" },
			{ chainId: 31338, name: "Devnet B" },
		]);
		assert.deepEqual(resolveChains({ CHAIN_NAME: "A" }, DEVNET), [
			{ chainId: 31337, name: "A" },
			{ chainId: 31338, name: "Devnet B" },
		]);
	});

	it("keeps the devnet names when only the ids are overridden, as before", () => {
		assert.deepEqual(
			resolveChains({ CHAIN_ID: "1", CHAIN_B_ID: "2" }, DEVNET),
			[
				{ chainId: 1, name: "Devnet A" },
				{ chainId: 2, name: "Devnet B" },
			],
		);
	});

	it("drops Devnet B when CHAIN_B_ID is empty", () => {
		assert.deepEqual(resolveChains({ CHAIN_B_ID: "" }, DEVNET), [
			{ chainId: 31337, name: "Devnet A" },
		]);
	});
});
