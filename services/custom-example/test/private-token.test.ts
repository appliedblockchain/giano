import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeFunctionData, erc20Abi } from "viem";
import type { LedgerEntry } from "../src/lib/ledger.ts";
import {
	findLatestTransfer,
	isBalanceRefusal,
	OUTSIDER_FALLBACK_ADDRESS,
	otherAccount,
	parseAmount,
	readerKey,
	redactionOf,
	refusalReason,
	staleReaderKeys,
} from "../src/lib/private-token.ts";

const WALLET = "0xa25927650FB4562358350Add9981b0A4Eae5B821";

describe("redactionOf", () => {
	it("reads the Silent Data placeholders as hidden", () => {
		// What the local gateway answered for a bundle transaction read unsigned.
		const redaction = redactionOf({
			from: "0x0000000000000000000000000000000000000000",
			to: "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			input: "0x",
			value: "0x0",
		});
		assert.deepEqual(redaction, {
			hidden: true,
			calldataHidden: true,
			senderHidden: true,
			value: "0x0",
		});
	});

	it("reads a public chain's transaction as visible", () => {
		const redaction = redactionOf({
			from: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			to: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			input: "0x765e827f0000",
			value: "0x0",
		});
		assert.equal(redaction.hidden, false);
		assert.equal(redaction.calldataHidden, false);
		assert.equal(redaction.senderHidden, false);
	});
});

describe("refusalReason", () => {
	it("names the private token's refusal", () => {
		// viem's message for the gateway's answer to an outsider's balance read (task 9.1).
		const message = [
			'The contract function "balanceOf" reverted with the following signature:',
			"0xdb11736b",
			"",
			"Unable to decode signature",
		].join("\n");
		assert.equal(
			refusalReason(message),
			"UCEFUnauthorizedBalanceAccess (0xdb11736b): only the holder can read this balance",
		);
	});

	it("keeps another error's selector on the line", () => {
		const message =
			'The contract function "balanceOf" reverted with the following signature:\n0x12345678\n\nmore';
		assert.equal(
			refusalReason(message),
			'The contract function "balanceOf" reverted with the following signature: 0x12345678',
		);
	});

	it("is the first line otherwise", () => {
		assert.equal(
			refusalReason("HTTP request failed.\n\nStatus: 401"),
			"HTTP request failed.",
		);
	});
});

describe("otherAccount", () => {
	it("is the latest transfer's recipient", () => {
		const recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
		assert.equal(otherAccount(WALLET, recipient), recipient);
	});

	it("falls back to a fixed address without a recipient, or when the recipient is the wallet", () => {
		assert.equal(otherAccount(WALLET, undefined), OUTSIDER_FALLBACK_ADDRESS);
		assert.equal(
			otherAccount(WALLET, WALLET.toLowerCase()),
			OUTSIDER_FALLBACK_ADDRESS,
		);
		assert.equal(otherAccount(WALLET, "0x1234"), OUTSIDER_FALLBACK_ADDRESS);
	});
});

describe("isBalanceRefusal", () => {
	it("is true only for the private token's refusal", () => {
		assert.equal(
			isBalanceRefusal(
				'The contract function "balanceOf" reverted with the following signature:\n0xdb11736b',
			),
			true,
		);
		assert.equal(
			isBalanceRefusal("HTTP request failed.\n\nStatus: 502"),
			false,
		);
		assert.equal(
			isBalanceRefusal("The request took too long to respond."),
			false,
		);
		assert.equal(
			isBalanceRefusal("the wallet did not approve the read delegate"),
			false,
		);
	});
});

describe("staleReaderKeys", () => {
	const OTHER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
	const keys = [
		readerKey(1, WALLET),
		readerKey(2, WALLET),
		readerKey(3, WALLET),
	];

	it("keeps a reader while its chain's session has the same wallet, on any chain", () => {
		const accounts: Record<number, string> = {
			1: WALLET,
			2: WALLET.toLowerCase(),
			3: WALLET,
		};
		assert.deepEqual(
			staleReaderKeys(keys, (chainId) => accounts[chainId]),
			[],
		);
	});

	it("drops a reader whose session ended or changed account, whichever chain is selected", () => {
		const accounts: Record<number, string> = { 1: WALLET, 3: OTHER };
		assert.deepEqual(
			staleReaderKeys(keys, (chainId) => accounts[chainId]),
			[readerKey(2, WALLET), readerKey(3, WALLET)],
		);
	});
});

describe("parseAmount", () => {
	it("reads a decimal amount in base units, and an empty field as 0", () => {
		assert.equal(parseAmount("1.5", 18), 1_500_000_000_000_000_000n);
		assert.equal(parseAmount(" 100 ", 0), 100n);
		assert.equal(parseAmount("", 18), 0n);
	});

	it("rejects more decimal places than the token has, instead of rounding", () => {
		assert.throws(() => parseAmount("1.999", 0), /more than 0 decimal places/);
		assert.throws(() => parseAmount("1.005", 2), /more than 2 decimal places/);
		assert.throws(
			() => parseAmount("0.0000001", 6),
			/more than 6 decimal places/,
		);
		assert.equal(parseAmount("1.000", 0), 1n);
		assert.equal(parseAmount("1.25", 2), 125n);
	});

	it("rejects a negative amount and one that does not fit a uint256", () => {
		assert.throws(() => parseAmount("-5", 18), /negative/);
		assert.throws(
			() => parseAmount((2n ** 256n).toString(), 0),
			/does not fit a uint256/,
		);
		assert.equal(parseAmount((2n ** 256n - 1n).toString(), 0), 2n ** 256n - 1n);
	});
});

describe("findLatestTransfer", () => {
	const CHAIN_ID = 31337;
	const RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
	const TX_HASH = `0x${"ab".repeat(32)}`;
	const transfer = (fields: Record<string, unknown>) =>
		({
			section: "private-token",
			chainId: CHAIN_ID,
			account: WALLET,
			status: "confirmed",
			label: "Transfer 1 PTK",
			txHash: TX_HASH,
			params: [
				{
					data: encodeFunctionData({
						abi: erc20Abi,
						functionName: "transfer",
						args: [RECIPIENT, 1n],
					}),
				},
			],
			...fields,
		}) as unknown as LedgerEntry;

	it("finds the latest transfer and its recipient", () => {
		assert.deepEqual(findLatestTransfer([transfer({})], CHAIN_ID, WALLET), {
			txHash: TX_HASH,
			recipient: RECIPIENT,
		});
	});

	it("skips restored entries whose fields have the wrong type", () => {
		const entries = [
			transfer({ label: undefined }),
			transfer({ account: 42 }),
			transfer({ params: { data: "0x" } }),
			transfer({ txHash: 7 }),
			transfer({ txHash: `0x${"cd".repeat(32)}` }),
		];
		assert.deepEqual(findLatestTransfer(entries, CHAIN_ID, WALLET), {
			txHash: `0x${"cd".repeat(32)}`,
			recipient: RECIPIENT,
		});
	});

	it("reads no recipient from a request that is not an object or has no string data", () => {
		for (const params of [[null], [5], [{ data: 5 }], undefined])
			assert.deepEqual(
				findLatestTransfer([transfer({ params })], CHAIN_ID, WALLET),
				{ txHash: TX_HASH, recipient: undefined },
			);
	});
});
