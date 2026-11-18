import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { describe, it } from "node:test";
import type { ChainRegistry } from "../src/lib/chains.ts";
import type { LedgerAction, LedgerEntry } from "../src/lib/ledger.ts";

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
const ZERO = "0x0000000000000000000000000000000000000000";

/** Runs a send declared sponsored whose receipt names no paymaster: the account paid. */
async function selfPaidSend(note?: string): Promise<LedgerEntry> {
	const registry = {
		walletOrigin: "http://wallet.localhost",
		require: () => ({
			config: { name: "Local" },
			publicClient: { getBalance: () => Promise.resolve(1000n) },
		}),
		providerFor: () => ({}),
	} as unknown as ChainRegistry;
	const actions: LedgerAction[] = [];
	await runAction(
		{ registry, ledger: (action) => actions.push(action) },
		{
			section: "private-token",
			label: "Mint 1 GTPT",
			method: "eth_sendTransaction",
			chainId: CHAIN_ID,
			account: WALLET,
			declaredPayer: "sponsored",
		},
		async (api) => {
			api.update({
				receipt: { paymaster: ZERO, actualGasCost: "0x0", success: true },
			});
			if (note) api.update({ note });
		},
	);
	let entry: LedgerEntry | undefined;
	for (const action of actions) {
		if (action.type === "add") entry = action.entry;
		if (action.type === "update" && entry)
			entry = { ...entry, ...action.patch };
	}
	assert.ok(entry);
	return entry;
}

describe("runAction", () => {
	it("adds the payer mismatch to the note the action wrote", async () => {
		const entry = await selfPaidSend("balance not read after this send");
		assert.equal(entry.attribution?.matchesDeclared, false);
		assert.equal(
			entry.note,
			"balance not read after this send; payer differs from declaration",
		);
	});

	it("writes the payer mismatch alone when the action wrote no note", async () => {
		const entry = await selfPaidSend();
		assert.equal(entry.note, "payer differs from declaration");
	});
});
