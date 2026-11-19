import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeAbiParameters, type Hex } from "viem";
import {
	chargesNoGas,
	GAS_PRICE_ORACLE,
	type GasPriceReader,
} from "../gasless";

type Chain = {
	/** The latest block's base fee; null for a chain with legacy gas pricing. */
	baseFee: bigint | null;
	gasPrice?: bigint;
	/** The GasPriceOracle's L1 fee; undefined when the chain is not OP Stack. */
	l1Fee?: bigint;
	/** The oracle answers with no data. */
	emptyOracle?: boolean;
};

/** A reader for one chain, which records the reads made. */
function reader(chain: Chain) {
	const reads: string[] = [];
	const client: GasPriceReader = {
		async getBlock() {
			reads.push("getBlock");
			return { baseFeePerGas: chain.baseFee };
		},
		async getGasPrice() {
			reads.push("getGasPrice");
			return chain.gasPrice ?? 0n;
		},
		async getCode({ address }) {
			reads.push("getCode");
			assert.equal(address, GAS_PRICE_ORACLE);
			return chain.l1Fee === undefined ? "0x" : "0x6080";
		},
		async call({ to }) {
			reads.push("getL1Fee");
			assert.equal(to, GAS_PRICE_ORACLE);
			if (chain.emptyOracle) return { data: "0x" as Hex };
			return {
				data: encodeAbiParameters([{ type: "uint256" }], [chain.l1Fee ?? 0n]),
			};
		},
	};
	return { client, reads };
}

test("a chain with a base fee above 0 charges for gas, after one block read", async () => {
	const { client, reads } = reader({ baseFee: 251n, l1Fee: 5n });
	assert.equal(await chargesNoGas(client), false);
	assert.deepEqual(reads, ["getBlock"]);
});

test("a chain with base fee 0 and no GasPriceOracle charges nothing (copper-heron)", async () => {
	const { client, reads } = reader({ baseFee: 0n });
	assert.equal(await chargesNoGas(client), true);
	assert.deepEqual(reads, ["getBlock", "getGasPrice", "getCode"]);
});

test("a chain with base fee 0 that still asks for a tip charges for gas", async () => {
	const { client, reads } = reader({ baseFee: 0n, gasPrice: 1n });
	assert.equal(await chargesNoGas(client), false);
	assert.deepEqual(reads, ["getBlock", "getGasPrice"]);
});

test("a legacy chain is priced by eth_gasPrice", async () => {
	const charging = reader({ baseFee: null, gasPrice: 1_000_000_000n });
	assert.equal(await chargesNoGas(charging.client), false);
	assert.deepEqual(charging.reads, ["getBlock", "getGasPrice"]);

	const free = reader({ baseFee: null, gasPrice: 0n });
	assert.equal(await chargesNoGas(free.client), true);
});

test("an OP Stack chain with base fee 0 charges for gas while its L1 fee is above 0", async () => {
	const charging = reader({ baseFee: 0n, l1Fee: 1_000n });
	assert.equal(await chargesNoGas(charging.client), false);
	assert.deepEqual(charging.reads, [
		"getBlock",
		"getGasPrice",
		"getCode",
		"getL1Fee",
	]);

	const free = reader({ baseFee: 0n, l1Fee: 0n });
	assert.equal(await chargesNoGas(free.client), true);
});

test("a block and the chain type the caller already has are not read again", async () => {
	const known = reader({ baseFee: 0n, l1Fee: 1_000n });
	assert.equal(
		await chargesNoGas(known.client, {
			block: { baseFeePerGas: 0n },
			opStack: true,
		}),
		false,
	);
	assert.deepEqual(known.reads, ["getGasPrice", "getL1Fee"]);

	const declared = reader({ baseFee: 0n, l1Fee: 1_000n });
	assert.equal(await chargesNoGas(declared.client, { opStack: false }), true);
	assert.deepEqual(declared.reads, ["getBlock", "getGasPrice"]);
});

test("a failed read is thrown, never taken as gasless", async () => {
	const { client } = reader({ baseFee: 0n });
	client.getBlock = async () => {
		throw new Error("rpc down");
	};
	await assert.rejects(chargesNoGas(client), /rpc down/);

	const empty = reader({ baseFee: 0n, l1Fee: 0n, emptyOracle: true });
	await assert.rejects(chargesNoGas(empty.client), /returned no L1 fee/);
});
