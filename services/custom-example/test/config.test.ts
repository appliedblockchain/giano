import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { loadRuntimeConfig } from "../src/config.ts";

const PRIVATE_TOKEN = "0x530d79ef28d4c6407B021523b9F8b2333171E3ac";

/** Loads the configuration as the container injects it (window.__GIANO_CONFIG__ from /config.js). */
function load(chains: unknown[]) {
	(globalThis as { window?: unknown }).window = {
		__GIANO_CONFIG__: { walletUrl: "http://wallet.localhost", chains },
	};
	return loadRuntimeConfig();
}

const chain = (extra: Record<string, unknown> = {}) => ({
	chainId: 31337,
	name: "Local",
	rpcUrl: "http://localhost:54321",
	...extra,
});

describe("GIANO_CHAINS privateToken", () => {
	afterEach(() => {
		delete (globalThis as { window?: unknown }).window;
	});

	it("is kept for the chain that names it, and absent elsewhere", () => {
		const result = load([
			chain({ privateToken: PRIVATE_TOKEN }),
			chain({ chainId: 31338, name: "Other" }),
		]);
		assert.ok(result.ok);
		assert.equal(result.config.chains[0].privateToken, PRIVATE_TOKEN);
		assert.equal(result.config.chains[1].privateToken, undefined);
	});

	it("treats an empty value as unset, as envsubst renders an unset variable", () => {
		const result = load([chain({ privateToken: " " })]);
		assert.ok(result.ok);
		assert.equal(result.config.chains[0].privateToken, undefined);
	});

	it("names privateToken on the configuration-error screen when it is not a string", () => {
		for (const privateToken of [123, {}]) {
			const result = load([chain({ privateToken })]);
			assert.ok(!result.ok);
			assert.deepEqual(
				result.issues.map((issue) => issue.path),
				["chains.0.privateToken"],
			);
		}
	});

	it("names privateToken on the configuration-error screen when it is not an address", () => {
		const result = load([chain({ privateToken: "0x1234" })]);
		assert.equal(result.ok, false);
		assert.ok(!result.ok);
		assert.deepEqual(result.issues, [
			{
				path: "chains.0.privateToken",
				message: "must be a 0x-prefixed 20-byte address",
			},
		]);
	});
});
