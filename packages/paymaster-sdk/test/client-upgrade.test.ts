import { type Hex, keccak256, toBytes, toHex } from "viem";
import { describe, expect, it } from "vitest";
import {
	ERC1967_IMPLEMENTATION_SLOT,
	GianoPaymasterClient,
	type PaymasterPublicClient,
	type PaymasterWalletClient,
} from "../src/client";

const PROXY = "0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96" as const;
const IMPLEMENTATION = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" as const;

describe("ERC1967_IMPLEMENTATION_SLOT", () => {
	it("is keccak256('eip1967.proxy.implementation') - 1", () => {
		const slot =
			BigInt(keccak256(toBytes("eip1967.proxy.implementation"))) - 1n;
		expect(ERC1967_IMPLEMENTATION_SLOT).toBe(toHex(slot, { size: 32 }));
	});
});

describe("getImplementation", () => {
	it("reads the address from the slot, checksummed", async () => {
		const reads: { address: string; slot: Hex }[] = [];
		const publicClient = {
			getStorageAt: async (args: { address: string; slot: Hex }) => {
				reads.push(args);
				return `0x${"0".repeat(24)}${IMPLEMENTATION.slice(2).toLowerCase()}` as Hex;
			},
		} as unknown as PaymasterPublicClient;
		const client = new GianoPaymasterClient({ address: PROXY, publicClient });
		expect(await client.getImplementation()).toBe(IMPLEMENTATION);
		expect(reads).toEqual([
			{ address: PROXY, slot: ERC1967_IMPLEMENTATION_SLOT },
		]);
	});
});

describe("upgradeToAndCall", () => {
	it("simulates, then sends upgradeToAndCall with the call data, empty by default", async () => {
		const simulated: { functionName: string; args: readonly unknown[] }[] = [];
		const publicClient = {
			simulateContract: async (request: {
				functionName: string;
				args: readonly unknown[];
			}) => {
				simulated.push({
					functionName: request.functionName,
					args: request.args,
				});
				return { request };
			},
		} as unknown as PaymasterPublicClient;
		const walletClient = {
			account: { address: IMPLEMENTATION, type: "json-rpc" },
			writeContract: async () => `0x${"ab".repeat(32)}` as Hex,
		} as unknown as PaymasterWalletClient;
		const client = new GianoPaymasterClient({
			address: PROXY,
			publicClient,
			walletClient,
		});
		const result = await client.upgradeToAndCall(IMPLEMENTATION);
		expect(result.hash).toBe(`0x${"ab".repeat(32)}`);
		await client.upgradeToAndCall(IMPLEMENTATION, "0x1234");
		expect(simulated).toEqual([
			{ functionName: "upgradeToAndCall", args: [IMPLEMENTATION, "0x"] },
			{ functionName: "upgradeToAndCall", args: [IMPLEMENTATION, "0x1234"] },
		]);
	});
});
