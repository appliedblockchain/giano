import { RPC_ERRORS } from "@appliedblockchain/giano-wallet-transport";
import { describe, expect, it, vi } from "vitest";
import { createConnectionGrants } from "../src/grants";
import { createHostRequestHandler } from "../src/host";
import { createRequestStore } from "../src/requests";
import type { WalletRuntime, WalletRuntimes } from "../src/runtimes";

function fakeRuntime(
	chainId: number,
	{
		account = true,
		connectResult = ["0xabc"],
	}: { account?: boolean; connectResult?: unknown } = {},
) {
	let hasAccount = account;
	const calls: { method: string; params?: unknown }[] = [];
	const listeners = new Map<string, ((data: unknown) => void)[]>();
	/** Fires a provider event, as the real provider does on connect or sign-in. */
	const emit = (event: string, data: unknown) => {
		for (const listener of listeners.get(event) ?? []) listener(data);
	};
	const runtime = {
		chainId,
		chainName: `Chain ${chainId}`,
		provider: {
			getSmartAccount: () => (hasAccount ? {} : null),
			on: vi.fn((event: string, listener: (data: unknown) => void) => {
				listeners.set(event, [...(listeners.get(event) ?? []), listener]);
			}),
			request: vi.fn(
				async ({ method, params }: { method: string; params?: unknown }) => {
					calls.push({ method, params });
					if (method === "giano_restoreAccount") {
						hasAccount = true;
						return undefined;
					}
					if (method === "eth_chainId") return `0x${chainId.toString(16)}`;
					if (method === "eth_requestAccounts") {
						if (Array.isArray(connectResult) && connectResult.length > 0)
							emit("accountsChanged", connectResult);
						return connectResult;
					}
					return `result:${method}`;
				},
			),
		},
	} as unknown as WalletRuntime;
	return { runtime, calls, emit };
}

const DAPP = "https://app.test";

function harness(
	chainId = 31337,
	options: {
		account?: boolean;
		connectResult?: unknown;
		/** Whether the dApp origin already holds a connection grant (WK-34). */
		connected?: boolean;
	} = {},
) {
	const { connected = true, ...runtimeOptions } = options;
	const { runtime, calls, emit } = fakeRuntime(chainId, runtimeOptions);
	const runtimes: WalletRuntimes = {
		servedChainIds: [chainId],
		runtimeFor: (id) => {
			if (id !== chainId) throw new Error(`does not serve ${id}`);
			return runtime;
		},
		descriptorFor: () => ({ chainId, name: `Chain ${chainId}` }) as never,
	};
	const requests = createRequestStore();
	const grants = createConnectionGrants(null);
	if (connected) grants.grant(DAPP);
	const sendEvent = vi.fn();
	const handler = createHostRequestHandler({
		runtimes,
		requests,
		grants,
		sendEvent,
	});
	const context = { dappOrigin: DAPP, chainId };
	return {
		handler,
		requests,
		calls,
		context,
		runtime,
		grants,
		emit,
		sendEvent,
	};
}

describe("the host request handler (WK-08…WK-12)", () => {
	it("refuses wallet_switchEthereumChain with the typed 4200 error (WK-11, MC-14)", async () => {
		const { handler, context } = harness();
		for (const method of [
			"wallet_switchEthereumChain",
			"wallet_addEthereumChain",
		]) {
			await expect(
				handler(method, [{ chainId: "0x1" }], context),
			).rejects.toMatchObject({ code: RPC_ERRORS.UNSUPPORTED_METHOD });
		}
	});

	it("forwards read methods straight to the provider, with no consent", async () => {
		const { handler, requests, context } = harness();
		const result = await handler("eth_chainId", [], context);
		expect(result).toBe("0x7a69");
		expect(requests.current).toBeNull();
	});

	it("gates eth_requestAccounts behind a connect consent naming the chain (MC-80)", async () => {
		const { handler, requests, context } = harness();
		const call = handler("eth_requestAccounts", [], context);
		expect(requests.current).toMatchObject({
			kind: "connect",
			chainId: 31337,
			chainName: "Chain 31337",
			dappOrigin: "https://app.test",
		});
		requests.current!.approve();
		await expect(call).resolves.toEqual(["0xabc"]);
	});

	it("answers 4001 on rejection without touching the provider (WK-09)", async () => {
		const { handler, requests, calls, context } = harness();
		const call = handler("eth_sendTransaction", [{}], context);
		await Promise.resolve();
		requests.current!.reject();
		await expect(call).rejects.toMatchObject({
			code: RPC_ERRORS.USER_REJECTED,
		});
		expect(calls.map((entry) => entry.method)).not.toContain(
			"eth_sendTransaction",
		);
	});

	it("silently restores a lost account before asking consent, with no extra prompt (WK-12)", async () => {
		const { handler, requests, calls, context } = harness(31337, {
			account: false,
		});
		const call = handler("personal_sign", ["0x68690a", "0xabc"], context);
		// wait for the async restore to run before consent appears
		await vi.waitFor(() => expect(requests.current).not.toBeNull());
		expect(calls[0]).toMatchObject({ method: "giano_restoreAccount" });
		requests.current!.approve();
		await expect(call).resolves.toBe("result:personal_sign");
	});

	it.each(["eth_signUserOperation", "signed_eth_call"])(
		"restores and asks consent for %s",
		async (method) => {
			const { handler, requests, calls, context } = harness(31337, {
				account: false,
			});
			const call = handler(method, [{}], context);
			await vi.waitFor(() => expect(requests.current).not.toBeNull());
			expect(calls[0]).toMatchObject({ method: "giano_restoreAccount" });
			expect(requests.current).toMatchObject({ kind: "sign", method });
			requests.current!.reject();
			await expect(call).rejects.toMatchObject({
				code: RPC_ERRORS.USER_REJECTED,
			});
			expect(calls.map((entry) => entry.method)).not.toContain(method);
		},
	);

	it.each(["eth_prepareUserOperation", "eth_sendSignedUserOperation"])(
		"restores the account for %s without asking for another signature",
		async (method) => {
			const { handler, requests, calls, context } = harness(31337, {
				account: false,
			});
			await expect(handler(method, [{}], context)).resolves.toBe(
				`result:${method}`,
			);
			expect(calls.map((entry) => entry.method)).toEqual([
				"giano_restoreAccount",
				method,
			]);
			expect(requests.current).toBeNull();
		},
	);

	describe("connection grants (WK-34)", () => {
		const ACCOUNT_METHODS = [
			"eth_sendTransaction",
			"personal_sign",
			"eth_sign",
			"eth_signTypedData_v4",
			"eth_signUserOperation",
			"signed_eth_call",
			"eth_prepareUserOperation",
			"eth_sendSignedUserOperation",
		];

		it("refuses giano_restoreAccount from an application, connected or not", async () => {
			for (const connected of [true, false]) {
				const { handler, calls, context } = harness(31337, {
					account: false,
					connected,
				});
				await expect(
					handler("giano_restoreAccount", [], context),
				).rejects.toMatchObject({ code: RPC_ERRORS.UNSUPPORTED_METHOD });
				expect(calls).toEqual([]);
			}
		});

		it("answers eth_accounts with [] to an origin with no grant, without touching the provider", async () => {
			const { handler, calls, context } = harness(31337, { connected: false });
			await expect(handler("eth_accounts", [], context)).resolves.toEqual([]);
			expect(calls).toEqual([]);
		});

		it("forwards eth_accounts to the provider for a connected origin", async () => {
			const { handler, context } = harness();
			await expect(handler("eth_accounts", [], context)).resolves.toBe(
				"result:eth_accounts",
			);
		});

		it.each(ACCOUNT_METHODS)(
			"refuses %s with 4100 for an origin with no grant: no restore, no consent, no provider call",
			async (method) => {
				const sendEvent = vi.fn();
				const { runtime, calls } = fakeRuntime(31337, { account: false });
				const requests = createRequestStore();
				const handler = createHostRequestHandler({
					runtimes: {
						servedChainIds: [31337],
						runtimeFor: () => runtime,
						descriptorFor: () => ({}) as never,
					},
					requests,
					grants: createConnectionGrants(null),
					sendEvent,
				});
				await expect(
					handler(method, [{}], { dappOrigin: DAPP, chainId: 31337 }),
				).rejects.toMatchObject({ code: RPC_ERRORS.UNAUTHORIZED });
				expect(calls).toEqual([]);
				expect(requests.current).toBeNull();
				// The event relay is not even wired, so no accountsChanged can reach the origin.
				expect(runtime.provider.on).not.toHaveBeenCalled();
				expect(sendEvent).not.toHaveBeenCalled();
			},
		);

		it("records the grant when the user approves eth_requestAccounts, for that origin only", async () => {
			const { handler, requests, grants, context } = harness(31337, {
				connected: false,
			});
			const call = handler("eth_requestAccounts", [], context);
			requests.current!.approve();
			await expect(call).resolves.toEqual(["0xabc"]);
			expect(grants.has(DAPP)).toBe(true);

			await expect(
				handler("eth_prepareUserOperation", [{}], context),
			).resolves.toBe("result:eth_prepareUserOperation");
			await expect(
				handler("eth_prepareUserOperation", [{}], {
					...context,
					dappOrigin: "https://other.test",
				}),
			).rejects.toMatchObject({ code: RPC_ERRORS.UNAUTHORIZED });
		});

		it("records no grant when the user rejects the connect", async () => {
			const { handler, requests, grants, context } = harness(31337, {
				connected: false,
			});
			const call = handler("eth_requestAccounts", [], context);
			requests.current!.reject();
			await expect(call).rejects.toMatchObject({
				code: RPC_ERRORS.USER_REJECTED,
			});
			expect(grants.has(DAPP)).toBe(false);
		});

		it("records no grant when the approved connect establishes no account", async () => {
			const { handler, requests, grants, context } = harness(31337, {
				connected: false,
				connectResult: [],
			});
			const call = handler("eth_requestAccounts", [], context);
			requests.current!.approve();
			await expect(call).resolves.toEqual([]);
			expect(grants.has(DAPP)).toBe(false);
		});

		it("drops the grant on wallet_revokePermissions", async () => {
			const { handler, grants, context } = harness();
			await handler(
				"wallet_revokePermissions",
				[{ eth_accounts: {} }],
				context,
			);
			expect(grants.has(DAPP)).toBe(false);
			await expect(
				handler("eth_prepareUserOperation", [{}], context),
			).rejects.toMatchObject({ code: RPC_ERRORS.UNAUTHORIZED });
		});

		it("answers -32603 and keeps refusing the origin when the storage refuses the revoke", async () => {
			const saved = new Map([
				["giano:connection-grants", JSON.stringify([DAPP])],
			]);
			const storage = {
				getItem: (key: string) => saved.get(key) ?? null,
				setItem: () => {
					throw new Error("QuotaExceededError");
				},
			};
			const { runtime } = fakeRuntime(31337);
			const handler = createHostRequestHandler({
				runtimes: {
					servedChainIds: [31337],
					runtimeFor: () => runtime,
					descriptorFor: () => ({}) as never,
				},
				requests: createRequestStore(),
				grants: createConnectionGrants(storage),
			});
			const context = { dappOrigin: DAPP, chainId: 31337 };
			await expect(
				handler("wallet_revokePermissions", [{ eth_accounts: {} }], context),
			).rejects.toMatchObject({ code: RPC_ERRORS.INTERNAL });
			await expect(
				handler("eth_prepareUserOperation", [{}], context),
			).rejects.toMatchObject({ code: RPC_ERRORS.UNAUTHORIZED });
		});

		it("does not relay accountsChanged to an origin with no grant that signs in from the management view", async () => {
			const { handler, requests, context, emit, sendEvent } = harness(31337, {
				connected: false,
			});
			const call = handler("giano_openWalletManagement", [], context);
			await vi.waitFor(() => expect(requests.current).not.toBeNull());
			// Sign in from the management view: the provider emits the address.
			emit("accountsChanged", ["0xabc"]);
			emit("chainChanged", "0x7a69");
			requests.current!.approve();
			await expect(call).resolves.toBeNull();
			expect(sendEvent).not.toHaveBeenCalledWith(
				"accountsChanged",
				expect.anything(),
			);
			expect(sendEvent).toHaveBeenCalledWith("chainChanged", "0x7a69");
		});

		it("relays accountsChanged once the origin holds a grant, and stops after a revoke", async () => {
			const { handler, requests, context, emit, sendEvent } = harness(31337, {
				connected: false,
			});
			const call = handler("eth_requestAccounts", [], context);
			requests.current!.approve();
			await expect(call).resolves.toEqual(["0xabc"]);
			// The connect emitted before the grant existed, so that event was dropped.
			expect(sendEvent).not.toHaveBeenCalled();

			emit("accountsChanged", ["0xdef"]);
			expect(sendEvent).toHaveBeenCalledWith("accountsChanged", ["0xdef"]);

			sendEvent.mockClear();
			await handler(
				"wallet_revokePermissions",
				[{ eth_accounts: {} }],
				context,
			);
			emit("accountsChanged", ["0xdef"]);
			expect(sendEvent).not.toHaveBeenCalled();
		});

		it("maps the provider's 4200 refusal of an unsupported method to the transport's 4200", async () => {
			const { handler, runtime, context } = harness();
			vi.mocked(runtime.provider.request).mockRejectedValueOnce(
				Object.assign(new Error("anvil_setBalance is not supported"), {
					code: 4200,
				}),
			);
			await expect(
				handler("anvil_setBalance", [], context),
			).rejects.toMatchObject({ code: RPC_ERRORS.UNSUPPORTED_METHOD });
		});
	});

	describe("giano_openWalletManagement (WM-54, WM-55)", () => {
		it("refuses parameters from the application (WM-39)", async () => {
			const { handler, context } = harness();
			await expect(
				handler("giano_openWalletManagement", [{ preselect: "x" }], context),
			).rejects.toMatchObject({
				code: RPC_ERRORS.UNSUPPORTED_METHOD,
			});
		});

		it("surfaces a manage request and returns nothing to the dApp (WM-40)", async () => {
			const { handler, requests, context } = harness();
			const call = handler("giano_openWalletManagement", [], context);
			await vi.waitFor(() => expect(requests.current).not.toBeNull());
			expect(requests.current).toMatchObject({
				kind: "manage",
				params: undefined,
			});
			requests.current!.approve(); // the user closed the management view
			await expect(call).resolves.toBeNull();
		});
	});
});
