import { createWalletApiInjection } from "@appliedblockchain/giano-wallet-core";
import { defineChain } from "viem";
import { describe, expect, it, vi } from "vitest";
import type { WalletChainConfig, WalletConfig } from "../src/config";
import {
	bundlerOptions,
	createWalletRuntimes,
	sessionHttp,
} from "../src/runtimes";

const chain = (chainId: number): WalletChainConfig => ({
	chainId,
	name: `Chain ${chainId}`,
	rpcUrl: `http://rpc-${chainId}.local`,
	bundlerUrl: `http://bundler-${chainId}.local`,
	factoryAddress: "0x1111111111111111111111111111111111111111",
	sponsorship: "off",
	paymasterServiceUrl: "/api/v1/paymaster",
});

const config: WalletConfig = {
	chains: [chain(31337), chain(31338)],
	walletApiUrl: "/api",
	allowedDappOrigins: ["https://app.test"],
	rpId: "wallet.test",
	branding: { name: "Test Wallet" },
};

describe("createWalletRuntimes (WK-01…WK-03)", () => {
	it("resolves runtimes lazily and memoises per chain (WK-02, MC-44)", () => {
		const runtimes = createWalletRuntimes(config);
		const first = runtimes.runtimeFor(31337);
		expect(runtimes.runtimeFor(31337)).toBe(first);
		expect(runtimes.servedChainIds).toEqual([31337, 31338]);
	});

	it("shares ONE wallet-api injection across all runtimes (WK-03, MC-76)", () => {
		const runtimes = createWalletRuntimes(config);
		const a = runtimes.runtimeFor(31337);
		const b = runtimes.runtimeFor(31338);
		expect(a).not.toBe(b);
		expect(a.injection).toBe(b.injection);
		expect(a.externalUserId).toBe(b.externalUserId);
	});

	it("refuses a chain outside the served list", () => {
		const runtimes = createWalletRuntimes(config);
		expect(() => runtimes.runtimeFor(1)).toThrow(/does not serve chain 1/);
		expect(() => runtimes.descriptorFor(1)).toThrow(/does not serve chain 1/);
	});

	it("fails fatally on an empty chain list", () => {
		expect(() => createWalletRuntimes({ ...config, chains: [] })).toThrow(
			/at least one chain/,
		);
	});

	it("answers not-applicable to the pre-flight when sponsorship is off (R-09)", async () => {
		const runtimes = createWalletRuntimes(config);
		await expect(
			runtimes.runtimeFor(31337).checkSponsorship({}),
		).resolves.toEqual({ state: "not-applicable" });
	});
});

describe("fee-before-paymaster is held by construction (WK-04, WK-27)", () => {
	const viemChain = defineChain({
		id: 31337,
		name: "Devnet",
		nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
		rpcUrls: { default: { http: ["http://rpc.local"] } },
	});
	const estimate = async () => ({ maxFeePerGas: 2n, maxPriorityFeePerGas: 1n });
	const stubClient = {
		getPaymasterData: async () => ({}),
		getPaymasterStubData: async () => ({}),
	} as never;
	const plainFetch = ((input: RequestInfo | URL, init?: RequestInit) =>
		globalThis.fetch(input, init)) as typeof fetch;

	it("always wires the fee estimator into userOperation, in every sponsorship mode", async () => {
		for (const descriptor of [
			chain(31337),
			{ ...chain(31337), sponsorship: "service" as const },
			{
				...chain(31337),
				sponsorship: "test-paymaster" as const,
				testPaymasterAddress:
					"0x2222222222222222222222222222222222222222" as const,
			},
		]) {
			const options = bundlerOptions(
				descriptor,
				viemChain,
				estimate,
				descriptor.sponsorship === "service" ? stubClient : undefined,
				plainFetch,
			);
			// viem populates fees during prepareUserOperation via this hook — BEFORE the
			// paymaster hooks run. There is no construction path without it.
			await expect(options.userOperation.estimateFeesPerGas()).resolves.toEqual(
				{ maxFeePerGas: 2n, maxPriorityFeePerGas: 1n },
			);
		}
	});

	it("attaches paymaster hooks only alongside the fee hook", () => {
		const sponsored = bundlerOptions(
			{ ...chain(31337), sponsorship: "service" },
			viemChain,
			estimate,
			stubClient,
			plainFetch,
		);
		expect("paymaster" in sponsored && sponsored.paymaster).toBeTruthy();
		expect(sponsored.userOperation.estimateFeesPerGas).toBeTypeOf("function");

		const off = bundlerOptions(
			chain(31337),
			viemChain,
			estimate,
			undefined,
			plainFetch,
		);
		expect("paymaster" in off).toBe(false);
	});

	it("refuses test-paymaster mode without an address", () => {
		expect(() =>
			bundlerOptions(
				{ ...chain(31337), sponsorship: "test-paymaster" },
				viemChain,
				estimate,
				undefined,
				plainFetch,
			),
		).toThrow(/no testPaymasterAddress/);
	});
});

describe("the bundler transport carries the wallet-api session", () => {
	const RELAY = "https://wallet.test/api/v1/bundler/31337";
	const respond = (status: number) =>
		vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			const { id } = JSON.parse(String(init?.body)) as { id: number };
			return new Response(
				JSON.stringify(
					status === 200
						? { jsonrpc: "2.0", id, result: "0x7a69" }
						: { error: "unauthorized" },
				),
				{ status, headers: { "content-type": "application/json" } },
			);
		});
	const injectionWith = (fetchImpl: ReturnType<typeof respond>) => {
		const injection = createWalletApiInjection({
			apiUrl: "https://wallet.test/api",
			externalUserId: "u",
			sessionToken: "session-token",
			fetch: fetchImpl as never,
		});
		const ended = vi.fn();
		injection.onSessionEnded(ended);
		return { injection, ended };
	};
	const header = (call: unknown[], name: string) =>
		new Headers((call[1] as RequestInit).headers).get(name);

	it("sends the bearer read at call time, so the session as it is now is what goes", async () => {
		const fetchMock = respond(200);
		const { injection } = injectionWith(fetchMock);
		const transport = sessionHttp(
			RELAY,
			injection.sessionFetch,
		)({
			retryCount: 0,
		});

		await transport.request({ method: "eth_chainId" });
		expect(header(fetchMock.mock.calls[0], "authorization")).toBe(
			"Bearer session-token",
		);
		expect(header(fetchMock.mock.calls[0], "content-type")).toBe(
			"application/json",
		);
		expect(String(fetchMock.mock.calls[0][0])).toBe(RELAY);

		injection.onUnauthorized();
		await transport.request({ method: "eth_chainId" });
		expect(header(fetchMock.mock.calls[1], "authorization")).toBeNull();
	});

	it("ends the session on wallet-api's 401, and only then (G5)", async () => {
		const fetchMock = respond(503);
		const { injection, ended } = injectionWith(fetchMock);
		const transport = sessionHttp(
			RELAY,
			injection.sessionFetch,
		)({
			retryCount: 0,
		});

		await expect(
			transport.request({ method: "eth_chainId" }),
		).rejects.toThrow();
		expect(ended).not.toHaveBeenCalled();

		fetchMock.mockImplementation(respond(401));
		const refused = await transport
			.request({ method: "eth_chainId" })
			.catch((error: unknown) => error);
		// what the host reads to answer 4100: the status, and that the URL is wallet-api's
		expect((refused as { status?: number }).status).toBe(401);
		expect(injection.isWalletApiUrl((refused as { url: string }).url)).toBe(
			true,
		);
		expect(ended).toHaveBeenCalledExactlyOnceWith("unauthorized");
		expect(injection.getSessionToken()).toBeNull();
	});

	it("sends a bundler dialled directly no token, and its 401 does not end the session", async () => {
		const fetchMock = respond(401);
		const { injection, ended } = injectionWith(fetchMock);
		const transport = sessionHttp(
			"https://bundler.example/rpc",
			injection.sessionFetch,
		)({ retryCount: 0 });

		await expect(
			transport.request({ method: "eth_chainId" }),
		).rejects.toThrow();
		expect(header(fetchMock.mock.calls[0], "authorization")).toBeNull();
		expect(ended).not.toHaveBeenCalled();
		expect(injection.getSessionToken()).toBe("session-token");
	});
});
