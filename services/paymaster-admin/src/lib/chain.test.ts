import { afterEach, describe, expect, it, vi } from "vitest";
import type { Deployment } from "../config";
import { createReadClient } from "./chain";

const deployment = {
	name: "test",
	chainId: 31337,
	rpcUrl: "http://rpc.test/",
	nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
} as unknown as Deployment;

describe("createReadClient with a session", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("sends the current token on each request, and names the token a 401 refused", async () => {
		const sent: string[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_input: unknown, init?: RequestInit) => {
				sent.push(new Headers(init?.headers).get("authorization") ?? "");
				return new Response("unauthorized", { status: 401 });
			}),
		);
		let token = "old";
		const refused: string[] = [];
		const client = createReadClient(deployment, {
			token: () => token,
			onUnauthorized: (which) => refused.push(which),
		});

		await client.getBlockNumber({ cacheTime: 0 }).catch(() => undefined);
		token = "new";
		await client.getBlockNumber({ cacheTime: 0 }).catch(() => undefined);

		expect(sent).toEqual(expect.arrayContaining(["Bearer old", "Bearer new"]));
		// each refusal names the token that request carried, so a replaced one can be told apart
		expect(new Set(refused)).toEqual(new Set(["old", "new"]));
	});
});
