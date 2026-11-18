import { type Hex, keccak256, toBytes, toHex } from "viem";
import { describe, expect, it } from "vitest";
import {
	ERC1967_IMPLEMENTATION_SLOT,
	GianoPaymasterClient,
	IMPLEMENTATION_LOG_REQUESTS_PER_READ,
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
		// From the slot: verified.
		expect(await client.readImplementationWithSource()).toEqual({
			address: IMPLEMENTATION,
			source: "slot",
		});
	});
});

describe("getImplementation on an empty slot", () => {
	it("says the address is not a proxy, rather than report the zero address", async () => {
		const publicClient = {
			getStorageAt: async () => `0x${"0".repeat(64)}` as Hex,
		} as unknown as PaymasterPublicClient;
		const client = new GianoPaymasterClient({ address: PROXY, publicClient });
		await expect(client.getImplementation()).rejects.toThrow(
			/has no ERC-1967 implementation/,
		);
	});
});

describe("readImplementationSlot on an RPC that refuses eth_getStorageAt", () => {
	it("reads the latest Upgraded event, in spans the platform read relay accepts", async () => {
		const UPGRADED_TOPIC =
			"0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
		const UPGRADED_AT = 9_000n;
		const spans: { from: bigint; to: bigint }[] = [];
		let head = 25_000n;
		const publicClient = {
			getStorageAt: async () => {
				throw new Error("method eth_getStorageAt is not allowed");
			},
			getBlockNumber: async () => head,
			request: async ({
				method,
				params,
			}: {
				method: string;
				params: [
					{
						address: string;
						topics: string[];
						fromBlock: Hex;
						toBlock: Hex;
					},
				];
			}) => {
				expect(method).toBe("eth_getLogs");
				const [filter] = params;
				expect(filter.address).toBe(PROXY);
				expect(filter.topics).toEqual([UPGRADED_TOPIC]);
				const from = BigInt(filter.fromBlock);
				const to = BigInt(filter.toBlock);
				spans.push({ from, to });
				return from <= UPGRADED_AT && UPGRADED_AT <= to
					? [
							{
								blockNumber: `0x${UPGRADED_AT.toString(16)}`,
								topics: [
									UPGRADED_TOPIC,
									`0x${"0".repeat(24)}${IMPLEMENTATION.slice(2).toLowerCase()}`,
								],
							},
						]
					: [];
			},
		} as unknown as PaymasterPublicClient;
		const client = new GianoPaymasterClient({ address: PROXY, publicClient });

		expect(await client.readImplementationSlot()).toBe(IMPLEMENTATION);
		// newest span first, and the walk stops at the span that holds the event
		expect(spans).toEqual([
			{ from: 16_001n, to: 25_000n },
			{ from: 7_001n, to: 16_000n },
		]);
		// rpc-read-relay.ts refuses an eth_getLogs span wider than PLATFORM_RPC_MAX_LOG_BLOCKS,
		// which may be as low as 9,000, counted inclusively
		for (const { from, to } of spans)
			expect(to - from + 1n).toBeLessThanOrEqual(9_000n);

		// A read on every block (the console's health check) does not repeat the walk: it reads only
		// the blocks after the checkpoint, 64 blocks behind the head, in one request.
		expect(await client.readImplementationSlot()).toBe(IMPLEMENTATION);
		expect(spans.slice(2)).toEqual([{ from: 24_937n, to: 25_000n }]);
		head = 25_002n;
		expect(await client.readImplementationSlot()).toBe(IMPLEMENTATION);
		expect(spans.slice(3)).toEqual([{ from: 24_937n, to: 25_002n }]);
	});
});

describe("readImplementationWithSource bounds each read", () => {
	/** Refuses eth_getStorageAt; no Upgraded event below `upgradedAt` is ever returned. */
	function refusing(head: bigint, upgradedAt: bigint) {
		const spans: { from: bigint; to: bigint }[] = [];
		const publicClient = {
			getStorageAt: async () => {
				throw new Error("JSON RPC method not whitelisted");
			},
			getBlockNumber: async () => head,
			request: async ({
				params: [filter],
			}: {
				params: [{ fromBlock: Hex; toBlock: Hex }];
			}) => {
				const from = BigInt(filter.fromBlock);
				const to = BigInt(filter.toBlock);
				spans.push({ from, to });
				return from <= upgradedAt && upgradedAt <= to
					? [
							{
								blockNumber: `0x${upgradedAt.toString(16)}`,
								topics: [
									"0x",
									`0x${"0".repeat(24)}${IMPLEMENTATION.slice(2).toLowerCase()}`,
								],
							},
						]
					: [];
			},
		} as unknown as PaymasterPublicClient;
		return { publicClient, spans };
	}

	it("sends at most IMPLEMENTATION_LOG_REQUESTS_PER_READ requests, and the next read continues", async () => {
		// The only upgrade is 150 spans back from the head.
		const { publicClient, spans } = refusing(10_000_000n, 8_650_000n);
		const client = new GianoPaymasterClient({ address: PROXY, publicClient });
		await expect(client.readImplementationWithSource()).rejects.toThrow(
			/no Upgraded event/,
		);
		expect(spans).toHaveLength(IMPLEMENTATION_LOG_REQUESTS_PER_READ);
		expect(await client.readImplementationWithSource()).toEqual({
			address: IMPLEMENTATION,
			source: "logs",
		});
	});

	it("starts at the configured deployment block, which a client rebound to a wallet keeps", async () => {
		const { publicClient, spans } = refusing(10_000_000n, 9_999_000n);
		const client = new GianoPaymasterClient({
			address: PROXY,
			publicClient,
			deployBlock: 9_999_000n,
		}).withWallet({} as PaymasterWalletClient);
		expect(await client.readImplementationSlot()).toBe(IMPLEMENTATION);
		expect(spans).toEqual([{ from: 9_999_000n, to: 10_000_000n }]);
	});
});

describe("upgradeToAndCall", () => {
	it("simulates, then sends upgradeToAndCall with the call data, empty by default", async () => {
		const simulated: { functionName: string; args: readonly unknown[] }[] = [];
		const publicClient = {
			estimateContractGas: async () => 100_000n,
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
		const written: { gas?: bigint }[] = [];
		const walletClient = {
			account: { address: IMPLEMENTATION, type: "json-rpc" },
			writeContract: async (request: { gas?: bigint }) => {
				written.push(request);
				return `0x${"ab".repeat(32)}` as Hex;
			},
		} as unknown as PaymasterWalletClient;
		const client = new GianoPaymasterClient({
			address: PROXY,
			publicClient,
			walletClient,
		});
		const result = await client.upgradeToAndCall(IMPLEMENTATION);
		expect(result.hash).toBe(`0x${"ab".repeat(32)}`);
		await client.upgradeToAndCall(IMPLEMENTATION, "0x1234");
		// a fifth over the estimate: a bare estimate can be exactly the post-refund gas, and run out
		expect(written[0].gas).toBe(120_000n);
		expect(simulated).toEqual([
			{ functionName: "upgradeToAndCall", args: [IMPLEMENTATION, "0x"] },
			{ functionName: "upgradeToAndCall", args: [IMPLEMENTATION, "0x1234"] },
		]);
	});
});
