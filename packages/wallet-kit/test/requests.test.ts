import { SessionEndedError } from "@appliedblockchain/giano-wallet-core";
import {
	RPC_ERRORS,
	TransportRpcError,
} from "@appliedblockchain/giano-wallet-transport";
import { describe, expect, it } from "vitest";
import {
	createRequestStore,
	type PendingRequest,
	toRpcError,
} from "../src/requests";
import type { WalletRuntime } from "../src/runtimes";

const input = (
	overrides: Partial<Omit<PendingRequest, "approve" | "reject">> = {},
) => ({
	kind: "connect" as const,
	method: "eth_requestAccounts",
	params: undefined,
	dappOrigin: "https://app.test",
	chainId: 31337,
	chainName: "Devnet",
	runtime: {} as WalletRuntime,
	...overrides,
});

describe("the single-slot consent queue (WK-10)", () => {
	it("exposes the pending request as subscribable state and resolves on approve", async () => {
		const store = createRequestStore();
		const seen: (PendingRequest | null)[] = [];
		store.subscribe((pending) => seen.push(pending));

		const consent = store.requestConsent(input());
		expect(store.current?.kind).toBe("connect");
		expect(store.current?.chainName).toBe("Devnet");

		store.current!.approve();
		await expect(consent).resolves.toBeUndefined();
		expect(store.current).toBeNull();
		expect(seen).toEqual([
			null,
			expect.objectContaining({ kind: "connect" }),
			null,
		]);
	});

	it("maps a rejection to EIP-1193 4001 (WK-09)", async () => {
		const store = createRequestStore();
		const consent = store.requestConsent(input());
		store.current!.reject();
		await expect(consent).rejects.toMatchObject({
			code: RPC_ERRORS.USER_REJECTED,
		});
	});

	it("answers a request whose session ended with 4100, not 4001 (G5)", async () => {
		const store = createRequestStore();
		const consent = store.requestConsent(input({ kind: "transaction" }));
		store.current!.sessionEnded();
		await expect(consent).rejects.toMatchObject({
			code: RPC_ERRORS.UNAUTHORIZED,
		});
		expect(store.current).toBeNull();
	});

	it("refuses a second request while one is pending, rather than queueing silently", async () => {
		const store = createRequestStore();
		const first = store.requestConsent(input());
		await expect(
			store.requestConsent(
				input({ method: "eth_sendTransaction", kind: "transaction" }),
			),
		).rejects.toMatchObject({
			code: RPC_ERRORS.INTERNAL,
		});
		store.current!.approve();
		await first;
	});
});

describe("toRpcError", () => {
	it("maps a refused session to 4100 Unauthorized, never 4001 (G5)", () => {
		// as viem wraps what a paymaster hook threw
		const wrapped = new Error("prepare failed", {
			cause: new Error("hook failed", { cause: new SessionEndedError() }),
		});
		expect(toRpcError(wrapped).code).toBe(RPC_ERRORS.UNAUTHORIZED);
		// as viem reports the bundler relay's 401
		const http401 = Object.assign(new Error("HTTP request failed"), {
			status: 401,
		});
		expect(toRpcError(new Error("send failed", { cause: http401 })).code).toBe(
			RPC_ERRORS.UNAUTHORIZED,
		);
		const http503 = Object.assign(new Error("HTTP request failed"), {
			status: 503,
		});
		expect(toRpcError(http503).code).toBe(RPC_ERRORS.INTERNAL);
	});

	it("passes a TransportRpcError through", () => {
		const error = new TransportRpcError(RPC_ERRORS.UNSUPPORTED_METHOD, "nope");
		expect(toRpcError(error)).toBe(error);
	});

	it("maps a WebAuthn abort to 4001", () => {
		const abort = Object.assign(
			new Error("The operation either timed out or was not allowed"),
			{ name: "NotAllowedError" },
		);
		expect(toRpcError(abort).code).toBe(RPC_ERRORS.USER_REJECTED);
	});

	it("maps a lost session to 4900 so the dApp reconnects", () => {
		expect(toRpcError(new Error("Giano not connected")).code).toBe(
			RPC_ERRORS.DISCONNECTED,
		);
	});

	it("maps everything else to an internal error", () => {
		expect(toRpcError(new Error("boom")).code).toBe(RPC_ERRORS.INTERNAL);
	});
});
