import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import { RPC_ERRORS } from "@appliedblockchain/giano-wallet-transport";
import { type Address, encodeFunctionData, type Hex } from "viem";
import { describe, expect, it, vi } from "vitest";
import { createHostRequestHandler } from "../src/host";
import { createRequestStore } from "../src/requests";
import type { WalletRuntime, WalletRuntimes } from "../src/runtimes";

const ACCOUNT: Address = "0x1111111111111111111111111111111111111111";
const DAPP_CONTRACT: Address = "0x2222222222222222222222222222222222222222";
const ADD_OWNER: Hex = encodeFunctionData({
	abi: gianoSmartWalletAbi,
	functionName: "addOwnerAddress",
	args: ["0x3333333333333333333333333333333333333333"],
});

const execute = (target: Address, data: Hex = "0x"): Hex =>
	encodeFunctionData({
		abi: gianoSmartWalletAbi,
		functionName: "execute",
		args: [target, 0n, data],
	});

const executeBatch = (calls: { target: Address; data: Hex }[]): Hex =>
	encodeFunctionData({
		abi: gianoSmartWalletAbi,
		functionName: "executeBatch",
		args: [calls.map((call) => ({ ...call, value: 0n }))],
	});

/** A user operation whose callData only calls a dApp contract. */
const dappUserOp = () => ({
	sender: ACCOUNT,
	callData: execute(DAPP_CONTRACT),
});

function fakeRuntime(
	chainId: number,
	{ account = true }: { account?: boolean } = {},
) {
	let hasAccount = account;
	const calls: { method: string; params?: unknown }[] = [];
	const runtime = {
		chainId,
		chainName: `Chain ${chainId}`,
		provider: {
			getSmartAccount: () => (hasAccount ? { address: ACCOUNT } : null),
			on: vi.fn(),
			request: vi.fn(
				async ({ method, params }: { method: string; params?: unknown }) => {
					calls.push({ method, params });
					if (method === "giano_restoreAccount") {
						hasAccount = true;
						return undefined;
					}
					if (method === "eth_chainId") return `0x${chainId.toString(16)}`;
					return `result:${method}`;
				},
			),
		},
	} as unknown as WalletRuntime;
	return { runtime, calls };
}

function harness(chainId = 31337, options: { account?: boolean } = {}) {
	const { runtime, calls } = fakeRuntime(chainId, options);
	const runtimes: WalletRuntimes = {
		servedChainIds: [chainId],
		runtimeFor: (id) => {
			if (id !== chainId) throw new Error(`does not serve ${id}`);
			return runtime;
		},
		descriptorFor: () => ({ chainId, name: `Chain ${chainId}` }) as never,
	};
	const requests = createRequestStore();
	const handler = createHostRequestHandler({ runtimes, requests });
	const context = { dappOrigin: "https://app.test", chainId };
	return { handler, requests, calls, context, runtime };
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
		await expect(call).resolves.toBe("result:eth_requestAccounts");
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
			const call = handler(method, [dappUserOp()], context);
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
			const params =
				method === "eth_prepareUserOperation"
					? [[{ to: DAPP_CONTRACT, data: "0x" }]]
					: [dappUserOp()];
			await expect(handler(method, params, context)).resolves.toBe(
				`result:${method}`,
			);
			expect(calls.map((entry) => entry.method)).toEqual([
				"giano_restoreAccount",
				method,
			]);
			expect(requests.current).toBeNull();
		},
	);

	describe("self-calls from the application", () => {
		it.each([
			[
				"eth_sendTransaction to the account",
				"eth_sendTransaction",
				[{ to: ACCOUNT, data: ADD_OWNER }],
			],
			[
				"eth_sendTransaction to the account in another letter case",
				"eth_sendTransaction",
				[{ to: `0x${ACCOUNT.slice(2).toUpperCase()}`, data: ADD_OWNER }],
			],
			[
				"eth_prepareUserOperation with a self-call",
				"eth_prepareUserOperation",
				[[{ to: ACCOUNT, data: ADD_OWNER }]],
			],
			[
				"eth_prepareUserOperation with a self-call viem would encode",
				"eth_prepareUserOperation",
				[
					[
						{
							to: ACCOUNT,
							abi: gianoSmartWalletAbi,
							functionName: "addOwnerAddress",
							args: [DAPP_CONTRACT],
						},
					],
				],
			],
			[
				"eth_prepareUserOperation with a self-call in options.calls",
				"eth_prepareUserOperation",
				[[], { calls: [{ to: ACCOUNT, data: ADD_OWNER }] }],
			],
			[
				"eth_prepareUserOperation with self-call callData in options",
				"eth_prepareUserOperation",
				[[], { callData: execute(ACCOUNT, ADD_OWNER) }],
			],
			[
				"eth_signUserOperation with execute to the account",
				"eth_signUserOperation",
				[{ sender: ACCOUNT, callData: execute(ACCOUNT, ADD_OWNER) }],
			],
			[
				"eth_signUserOperation with a self-call inside executeBatch",
				"eth_signUserOperation",
				[
					{
						sender: ACCOUNT,
						callData: executeBatch([
							{ target: DAPP_CONTRACT, data: "0x" },
							{ target: ACCOUNT, data: ADD_OWNER },
						]),
					},
				],
			],
			[
				"eth_sendSignedUserOperation with execute to the account",
				"eth_sendSignedUserOperation",
				[{ sender: ACCOUNT, callData: execute(ACCOUNT, ADD_OWNER) }],
			],
		])(
			"refuses %s with 4100, before consent or the provider",
			async (_name, method, params) => {
				const { handler, requests, calls, context } = harness();
				await expect(handler(method, params, context)).rejects.toMatchObject({
					code: RPC_ERRORS.UNAUTHORIZED,
					message: expect.stringContaining("giano_openWalletManagement"),
				});
				expect(requests.current).toBeNull();
				expect(calls.map((entry) => entry.method)).not.toContain(method);
			},
		);

		it("refuses a self-call after restoring a lost account", async () => {
			const { handler, requests, calls, context } = harness(31337, {
				account: false,
			});
			await expect(
				handler(
					"eth_sendTransaction",
					[{ to: ACCOUNT, data: ADD_OWNER }],
					context,
				),
			).rejects.toMatchObject({ code: RPC_ERRORS.UNAUTHORIZED });
			expect(calls.map((entry) => entry.method)).toEqual([
				"giano_restoreAccount",
			]);
			expect(requests.current).toBeNull();
		});

		it.each([
			["eth_signUserOperation", [{ sender: ACCOUNT, callData: ADD_OWNER }]],
			["eth_signUserOperation", [{ sender: ACCOUNT }]],
			[
				"eth_signUserOperation",
				[
					{
						sender: ACCOUNT,
						callData: encodeFunctionData({
							abi: gianoSmartWalletAbi,
							functionName: "executeWithoutChainIdValidation",
							args: [[ADD_OWNER]],
						}),
					},
				],
			],
			["eth_sendSignedUserOperation", [{ sender: ACCOUNT, callData: "0x" }]],
			["eth_prepareUserOperation", [[], { callData: ADD_OWNER }]],
		])(
			"refuses %s whose callData is not execute or executeBatch",
			async (method, params) => {
				const { handler, requests, calls, context } = harness();
				await expect(handler(method, params, context)).rejects.toMatchObject({
					code: RPC_ERRORS.UNAUTHORIZED,
				});
				expect(requests.current).toBeNull();
				expect(calls.map((entry) => entry.method)).not.toContain(method);
			},
		);

		it.each([
			[
				"eth_sendTransaction to another contract",
				"eth_sendTransaction",
				[{ to: DAPP_CONTRACT, data: "0x" }],
				"transaction",
			],
			[
				"a value-only eth_sendTransaction to the account",
				"eth_sendTransaction",
				[{ to: ACCOUNT, value: "0x0" }],
				"transaction",
			],
			[
				"eth_signUserOperation with a value-only execute to the account",
				"eth_signUserOperation",
				[{ sender: ACCOUNT, callData: execute(ACCOUNT) }],
				"sign",
			],
		])("still asks consent for %s", async (_name, method, params, kind) => {
			const { handler, requests, context } = harness();
			const call = handler(method, params, context);
			await vi.waitFor(() => expect(requests.current).not.toBeNull());
			expect(requests.current).toMatchObject({ kind, method });
			requests.current!.approve();
			await expect(call).resolves.toBe(`result:${method}`);
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
