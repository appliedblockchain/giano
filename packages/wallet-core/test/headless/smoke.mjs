// Headless smoke test: run by test/headless.test.ts in a separate `node` process, against the
// built dist/. It proves that a backend can import wallet-core and use the account and
// management exports with no DOM, no React and no network.
//
// Every import is dynamic, so the DOM globals are removed before any module loads.
import assert from "node:assert/strict";
import { createRequire } from "node:module";

// Node 21+ defines `navigator`; browsers define the rest. None may be needed at import time.
delete globalThis.navigator;
for (const name of [
	"navigator",
	"window",
	"document",
	"self",
	"location",
	"localStorage",
	"sessionStorage",
	"PublicKeyCredential",
	"HTMLElement",
	"customElements",
]) {
	assert.equal(typeof globalThis[name], "undefined", `${name} is defined`);
}

const esm = await import("../../dist/index.mjs");
const cjs = createRequire(import.meta.url)("../../dist/index.js");

const { createPublicClient, custom, getAddress, isHex } = await import("viem");
const { foundry } = await import("viem/chains");
const { privateKeyToAccount } = await import("viem/accounts");

// Any RPC request fails the test: everything below must work offline.
const client = createPublicClient({
	chain: foundry,
	transport: custom({
		request: async ({ method }) => {
			throw new Error(`unexpected RPC request: ${method}`);
		},
	}),
});

// A fixed test key. It signs nothing outside this script.
const owner = privateKeyToAccount(`0x${"11".repeat(32)}`);
const address = getAddress(`0x${"ab".repeat(20)}`);
const factoryAddress = getAddress(`0x${"fa".repeat(20)}`);
const calls = [
	{ to: getAddress(`0x${"01".repeat(20)}`), value: 1n, data: "0x1234" },
	{ to: getAddress(`0x${"02".repeat(20)}`), value: 0n, data: "0x" },
];

for (const [format, core] of [
	["esm", esm],
	["cjs", cjs],
]) {
	// `account` exports: an account bound to an explicit address, with no factory lookup.
	const account = await core.toGianoSmartAccount({
		client,
		owners: [owner],
		address,
		factoryAddress,
	});
	assert.equal(await account.getAddress(), address, format);

	const callData = await account.encodeCalls(calls);
	assert.deepEqual(await account.decodeCalls(callData), calls, format);

	assert.ok(
		account.abi.some((item) => item.name === "isValidSignature"),
		`${format}: the account ABI has isValidSignature`,
	);

	const signature = await account.signUserOperation({
		callData,
		nonce: 0n,
		callGasLimit: 100_000n,
		verificationGasLimit: 100_000n,
		preVerificationGas: 50_000n,
		maxFeePerGas: 1n,
		maxPriorityFeePerGas: 1n,
		signature: "0x",
	});
	assert.ok(isHex(signature) && signature.length > 2, format);

	// `management` exports: owner encodings and the owner-change calldata.
	const ownerBytes = core.addressOwnerBytes(owner.address);
	assert.equal(
		core.classifyOwnerBytes(0, ownerBytes).address,
		owner.address.toLowerCase(),
		format,
	);
	assert.ok(isHex(core.encodeAddOwnerAddress(owner.address)), format);
}

console.log("wallet-core headless smoke: ok");
