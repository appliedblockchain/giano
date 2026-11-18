import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
	createPublicClient,
	type Hex,
	keccak256,
	recoverMessageAddress,
	stringToBytes,
} from "viem";
import {
	DELEGATE_LIFETIME_MS,
	DELEGATE_RENEW_MARGIN_MS,
	type DelegateTicket,
	delegateApprovalMessage,
	SignedReader,
} from "../src/lib/signed-reads.ts";

const CHAIN_ID = 31337;
const WALLET = "0xa25927650FB4562358350Add9981b0A4Eae5B821";
const START = Date.parse("2026-11-16T12:00:00.000Z");
const APPROVAL = `0x${"ab".repeat(100)}` as Hex;

/** A reader on a clock the test moves, with a wallet that records every prompt. */
function setup(options: { reject?: number } = {}) {
	let time = START;
	const prompts: Array<{ message: Hex; renewed: boolean }> = [];
	let rejections = options.reject ?? 0;
	const reader = new SignedReader({
		chainId: CHAIN_ID,
		wallet: WALLET,
		now: () => time,
		personalSign: async (message, { renewed }) => {
			prompts.push({ message, renewed });
			if (rejections > 0) {
				rejections -= 1;
				throw new Error("User rejected the request.");
			}
			return APPROVAL;
		},
	});
	return {
		reader,
		prompts,
		advance: (ms: number) => {
			time += ms;
		},
		at: (ms: number) => {
			time = ms;
		},
	};
}

const ticketOf = (headers: Record<string, string>) =>
	JSON.parse(headers["x-delegate"]) as DelegateTicket;

describe("delegateApprovalMessage", () => {
	it("is keccak256 of chainId + the ticket JSON, keys in the order the RPC reads them", () => {
		const ticket: DelegateTicket = {
			expires: "2026-11-16T13:00:00.000Z",
			ephemeralAddress: "0x00000000000000000000000000000000000000E1",
		};
		assert.equal(
			delegateApprovalMessage(CHAIN_ID, ticket),
			keccak256(
				stringToBytes(
					'31337{"expires":"2026-11-16T13:00:00.000Z","ephemeralAddress":"0x00000000000000000000000000000000000000E1"}',
				),
			),
		);
	});
});

describe("SignedReader headers", () => {
	it("sends the six gateway headers, signed by the delegate over chainId + body + timestamp", async () => {
		const { reader, prompts } = setup();
		const body = '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[]}';
		const headers = await reader.headers(body);

		assert.deepEqual(Object.keys(headers).sort(), [
			"x-delegate",
			"x-delegate-signature",
			"x-signature",
			"x-signer-swc",
			"x-signer-swc-type",
			"x-timestamp",
		]);
		assert.equal(headers["x-signer-swc"], WALLET);
		assert.equal(headers["x-signer-swc-type"], "giano");
		assert.equal(headers["x-timestamp"], "2026-11-16T12:00:00.000Z");
		assert.equal(headers["x-delegate-signature"], APPROVAL);

		const ticket = ticketOf(headers);
		assert.deepEqual(Object.keys(ticket), ["expires", "ephemeralAddress"]);
		assert.equal(Date.parse(ticket.expires), START + DELEGATE_LIFETIME_MS);
		assert.equal(
			await recoverMessageAddress({
				message: `${CHAIN_ID}${body}${headers["x-timestamp"]}`,
				signature: headers["x-signature"] as Hex,
			}),
			ticket.ephemeralAddress,
		);
		// The wallet approved exactly this ticket.
		assert.deepEqual(prompts, [
			{ message: delegateApprovalMessage(CHAIN_ID, ticket), renewed: false },
		]);
	});
});

describe("SignedReader approvals", () => {
	it("asks the wallet once for three reads", async () => {
		const { reader, prompts, advance } = setup();
		await reader.headers("a");
		advance(10 * 60 * 1000);
		await reader.headers("b");
		advance(10 * 60 * 1000);
		await reader.headers("c");
		assert.equal(prompts.length, 1);
	});

	it("asks the wallet once for concurrent reads", async () => {
		const { reader, prompts } = setup();
		const all = await Promise.all([
			reader.headers("a"),
			reader.headers("b"),
			reader.headers("c"),
		]);
		assert.equal(prompts.length, 1);
		assert.equal(new Set(all.map((h) => h["x-delegate"])).size, 1);
	});

	it("renews with a new key once the ticket is about to expire", async () => {
		const { reader, prompts, at } = setup();
		const first = ticketOf(await reader.headers("a"));
		const expiresAt = Date.parse(first.expires);

		at(expiresAt - DELEGATE_RENEW_MARGIN_MS - 1);
		await reader.headers("b");
		assert.equal(prompts.length, 1);
		assert.ok(reader.delegate);

		at(expiresAt - DELEGATE_RENEW_MARGIN_MS);
		assert.equal(reader.delegate, undefined);
		const second = ticketOf(await reader.headers("c"));
		assert.equal(prompts.length, 2);
		assert.equal(prompts[1].renewed, true);
		assert.notEqual(second.ephemeralAddress, first.ephemeralAddress);
		assert.equal(
			Date.parse(second.expires),
			expiresAt - DELEGATE_RENEW_MARGIN_MS + DELEGATE_LIFETIME_MS,
		);
	});

	it("asks again after the wallet refuses, without a delegate in between", async () => {
		const { reader, prompts } = setup({ reject: 1 });
		await assert.rejects(reader.headers("a"), /User rejected/);
		assert.equal(reader.delegate, undefined);
		await reader.headers("b");
		assert.equal(prompts.length, 2);
		assert.equal(prompts[1].renewed, false);
	});
});

describe("SignedReader transport", () => {
	const realFetch = globalThis.fetch;
	afterEach(() => {
		globalThis.fetch = realFetch;
	});

	it("signs the exact body viem sends", async () => {
		const sent: Array<{ body: string; headers: Headers }> = [];
		globalThis.fetch = async (_input, init) => {
			const body = String(init?.body);
			sent.push({ body, headers: new Headers(init?.headers) });
			const { id } = JSON.parse(body) as { id: number };
			return new Response(
				JSON.stringify({ jsonrpc: "2.0", id, result: `0x${"00".repeat(32)}` }),
				{ headers: { "content-type": "application/json" } },
			);
		};
		const { reader } = setup();
		const client = createPublicClient({
			transport: reader.transport("http://rpc.test"),
		});
		await client.call({
			account: WALLET,
			to: "0x530d79ef28d4c6407B021523b9F8b2333171E3ac",
			data: "0x70a08231",
		});

		assert.equal(sent.length, 1);
		const { body, headers } = sent[0];
		assert.match(body, /"method":"eth_call"/);
		const ticket = JSON.parse(
			headers.get("x-delegate") ?? "{}",
		) as DelegateTicket;
		assert.equal(
			await recoverMessageAddress({
				message: `${CHAIN_ID}${body}${headers.get("x-timestamp")}`,
				signature: headers.get("x-signature") as Hex,
			}),
			ticket.ephemeralAddress,
		);
		assert.equal(headers.get("x-signer-swc"), WALLET);
		assert.equal(headers.get("content-type"), "application/json");
	});

	it("after approved(), the request signs in memory and never waits for the wallet", async () => {
		const { reader, prompts } = setup();
		const delegate = await reader.approved();
		assert.equal(prompts.length, 1);
		assert.deepEqual(reader.delegate, delegate);

		const sent: Headers[] = [];
		globalThis.fetch = async (_input, init) => {
			sent.push(new Headers(init?.headers));
			const { id } = JSON.parse(String(init?.body)) as { id: number };
			return new Response(
				JSON.stringify({ jsonrpc: "2.0", id, result: "0x" }),
				{ headers: { "content-type": "application/json" } },
			);
		};
		// viem runs the request under its timeout, so the request must not ask the wallet again.
		const client = createPublicClient({
			transport: reader.transport("http://rpc.test"),
		});
		await client.call({
			account: WALLET,
			to: "0x530d79ef28d4c6407B021523b9F8b2333171E3ac",
			data: "0x70a08231",
		});

		assert.equal(prompts.length, 1);
		assert.equal(sent.length, 1);
		assert.deepEqual(
			JSON.parse(sent[0].get("x-delegate") ?? "{}"),
			delegate.ticket,
		);
		assert.equal(sent[0].get("x-delegate-signature"), delegate.approval);
	});

	it("approved() shares one prompt with a concurrent read, and returns at once while valid", async () => {
		const { reader, prompts } = setup();
		const [delegate, headers] = await Promise.all([
			reader.approved(),
			reader.headers("a"),
		]);
		assert.equal(prompts.length, 1);
		assert.deepEqual(ticketOf(headers), delegate.ticket);
		assert.equal(await reader.approved(), delegate);
		assert.equal(prompts.length, 1);
	});
});
