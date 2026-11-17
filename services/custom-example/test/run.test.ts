import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { describe, it } from "node:test";
import type { ChainRegistry } from "../src/lib/chains.ts";
import type { LedgerAction } from "../src/lib/ledger.ts";

// run.ts and its imports use extensionless relative imports (Vite resolves them). Node's test
// runner does not, so resolve "./x" to "./x.ts" here, then load run.ts after the hook is in place.
registerHooks({
	resolve(specifier, context, next) {
		try {
			return next(specifier, context);
		} catch (error) {
			if (specifier.startsWith(".") && !/\.[cm]?[jt]sx?$/.test(specifier))
				return next(`${specifier}.ts`, context);
			throw error;
		}
	},
});
const { runAction } = await import("../src/lib/run.ts");

const CHAIN_ID = 31337;
const WALLET = "0xa25927650FB4562358350Add9981b0A4Eae5B821";
const TOKEN = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const ZERO = "0x0000000000000000000000000000000000000000";

/** A registry whose public client answers balance reads from the given functions. */
function setup(reads: {
	getBalance: () => Promise<bigint>;
	balanceOf: () => Promise<bigint>;
}) {
	const calls: string[] = [];
	const entry = {
		config: { name: "Local" },
		publicClient: {
			getBalance: () => {
				calls.push("getBalance");
				return reads.getBalance();
			},
			readContract: () => {
				calls.push("balanceOf");
				return reads.balanceOf();
			},
		},
	};
	const registry = {
		walletOrigin: "http://wallet.localhost",
		require: () => entry,
		providerFor: () => ({}),
	} as unknown as ChainRegistry;
	const actions: LedgerAction[] = [];
	return {
		calls,
		ctx: { registry, ledger: (a: LedgerAction) => actions.push(a) },
	};
}

describe("runAction", () => {
	it("opens the action before the before-balance read resolves, and still records both balances", {
		timeout: 5000,
	}, async () => {
		let resolveNative: (value: bigint) => void = () => {};
		let resolveToken: (value: bigint) => void = () => {};
		const nativeBefore = new Promise<bigint>((r) => {
			resolveNative = r;
		});
		const tokenBefore = new Promise<bigint>((r) => {
			resolveToken = r;
		});
		let nativeReads = 0;
		let tokenReads = 0;
		const { calls, ctx } = setup({
			getBalance: () =>
				nativeReads++ === 0 ? nativeBefore : Promise.resolve(900n),
			balanceOf: () =>
				tokenReads++ === 0 ? tokenBefore : Promise.resolve(15n),
		});

		let beforeSettled = false;
		void Promise.all([nativeBefore, tokenBefore]).then(() => {
			beforeSettled = true;
		});
		let callsWhenOpened: string[] = [];
		const outcome = await runAction(
			ctx,
			{
				section: "private-token",
				label: "Mint",
				method: "eth_sendTransaction",
				chainId: CHAIN_ID,
				account: WALLET,
				token: TOKEN,
				declaredPayer: "self-paid",
			},
			async (api) => {
				// The wallet popup opens here: the before-read is already sent but not yet answered.
				callsWhenOpened = [...calls];
				assert.equal(beforeSettled, false);
				resolveNative(1000n);
				resolveToken(10n);
				api.update({
					receipt: { paymaster: ZERO, actualGasCost: "0x64", success: true },
				});
				return "done";
			},
		);

		assert.deepEqual(callsWhenOpened, ["getBalance", "balanceOf"]);
		assert.equal(outcome.result, "done");
		assert.equal(outcome.entry.status, "confirmed");
		assert.deepEqual(outcome.entry.balances, {
			token: TOKEN,
			nativeBefore: "1000",
			tokenBefore: "10",
			nativeAfter: "900",
			tokenAfter: "15",
		});
		assert.equal(outcome.entry.attribution?.actualPayer, "self-paid");
		assert.equal(outcome.entry.attribution?.nativeDelta, -100n);
		assert.equal(outcome.entry.attribution?.matchesDeclared, true);
	});

	it("records the action when the before-balance read fails", async () => {
		let nativeReads = 0;
		const { ctx } = setup({
			getBalance: () => {
				// A synchronous throw on the before-read: readBalances rejects, and runAction must catch it.
				if (nativeReads++ === 0) throw new Error("rpc down");
				return Promise.resolve(900n);
			},
			balanceOf: () => Promise.resolve(0n),
		});
		const outcome = await runAction(
			ctx,
			{
				section: "private-token",
				label: "Mint",
				method: "eth_sendTransaction",
				chainId: CHAIN_ID,
				account: WALLET,
			},
			async () => "done",
		);
		assert.equal(outcome.entry.status, "ok");
		assert.equal(outcome.entry.balances?.nativeBefore, undefined);
		assert.equal(outcome.entry.balances?.nativeAfter, "900");
	});
});
