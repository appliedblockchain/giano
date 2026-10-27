import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { test } from "node:test";
import { promisify } from "node:util";
import { type Address, type PublicClient, zeroAddress } from "viem";
import { CANONICAL_DEPLOYER, DEPLOYER_IS_PLACEHOLDER, LABELS } from "./config";
import { create3Address } from "./create3";
import {
	inspectTestnet,
	networkFor,
	roleAdmin,
	verifyCoreState,
} from "./testnet-checks";

const admin = "0x1111111111111111111111111111111111111111" as Address;
function client(overrides: object = {}): PublicClient {
	return {
		getChainId: async () => 84532,
		getCode: async () => undefined,
		getBalance: async () => 0n,
		...overrides,
	} as unknown as PublicClient;
}

test("target selection refuses unsupported networks and object prototype keys", () => {
	assert.equal(networkFor("base-sepolia"), "base-sepolia");
	assert.equal(networkFor("ethereum-sepolia"), "ethereum-sepolia");
	for (const name of ["base", "mainnet", "8453", "__proto__", "toString", ""])
		assert.throws(() => networkFor(name));
	assert.throws(() => roleAdmin(zeroAddress));
	assert.throws(() => roleAdmin("invalid"));
});

test("wrong-chain RPC stops before inspecting addresses or balances", async () => {
	let reads = 0;
	const checks = await inspectTestnet(
		client({
			getChainId: async () => 1,
			getCode: async () => {
				reads++;
			},
		}),
		"base-sepolia",
		"v1",
		admin,
	);
	assert.equal(checks.length, 1);
	assert.equal(checks[0].ok, false);
	assert.match(checks[0].message, /Wrong chain/);
	assert.equal(reads, 0);
});

test("missing dependencies and foreign bytecode are reported together", async () => {
	const checks = await inspectTestnet(
		client({
			getCode: async ({ address }: { address: Address }) =>
				address ===
				create3Address(CANONICAL_DEPLOYER, LABELS.walletImplementation)
					? "0x6000"
					: "0x",
		}),
		"base-sepolia",
		"v1",
		admin,
	);
	assert.ok(checks.some((c) => !c.ok && /CreateX/.test(c.message)));
	assert.ok(checks.some((c) => !c.ok && /EntryPoint/.test(c.message)));
	assert.ok(checks.some((c) => !c.ok && /Occupied/.test(c.message)));
});

test("RPC errors cannot disclose provider credentials", async () => {
	const checks = await inspectTestnet(
		client({
			getChainId: async () => {
				throw new Error("https://provider.invalid/SECRET_API_KEY");
			},
		}),
		"base-sepolia",
		"v1",
		admin,
	);
	assert.equal(checks[0].ok, false);
	assert.doesNotMatch(JSON.stringify(checks), /SECRET_API_KEY/);
	assert.match(checks[0].message, /endpoint access/);
});

test("stale generated release data blocks adoption", async () => {
	const checks = await inspectTestnet(
		client(),
		"base-sepolia",
		"v99999",
		admin,
	);
	assert.equal(
		checks.filter(
			(c) => !c.ok && /Canonical release data is stale/.test(c.message),
		).length,
		4,
	);
});

test("absent contracts require no storage reads, including providers returning 0x", async () => {
	await verifyCoreState(client({ getCode: async () => "0x" }), admin);
});

test("existing proxy storage must point to the planned implementation", async () => {
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	await assert.rejects(
		verifyCoreState(
			client({
				getCode: async ({ address }: { address: Address }) =>
					address === proxy ? "0x6000" : undefined,
				getStorageAt: async () => `0x${"0".repeat(64)}`,
			}),
			admin,
		),
		/unexpected implementation/,
	);
});

test("an existing paymaster with the wrong role admin is rejected", async () => {
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	const implementation = create3Address(
		CANONICAL_DEPLOYER,
		LABELS.paymasterImplementation,
	);
	await assert.rejects(
		verifyCoreState(
			client({
				getCode: async ({ address }: { address: Address }) =>
					address === proxy ? "0x6000" : undefined,
				getStorageAt: async () =>
					`0x${"0".repeat(24)}${implementation.slice(2)}`,
				readContract: async ({ functionName }: { functionName: string }) =>
					functionName === "hasRole" ? false : 0n,
			}),
			admin,
		),
	);
});

test("CLI --plan is read-only and reports the placeholder on both supported networks", async () => {
	for (const chainId of [84532, 11155111]) {
		const methods: string[] = [];
		const server = createServer(async (req, res) => {
			let body = "";
			for await (const chunk of req) body += chunk;
			const request = JSON.parse(body);
			methods.push(request.method);
			res.setHeader("Content-Type", "application/json");
			res.end(
				JSON.stringify({
					jsonrpc: "2.0",
					id: request.id,
					result:
						request.method === "eth_chainId"
							? `0x${chainId.toString(16)}`
							: "0x",
				}),
			);
		});
		await new Promise<void>((resolve) =>
			server.listen(0, "127.0.0.1", resolve),
		);
		const address = server.address();
		assert.ok(address && typeof address !== "string");
		try {
			await promisify(execFile)(
				process.execPath,
				[
					"--import",
					"tsx",
					"deploy/testnet.ts",
					"--plan",
					"--network",
					chainId === 84532 ? "base-sepolia" : "ethereum-sepolia",
					"--rpc",
					`http://127.0.0.1:${address.port}`,
					"--role-admin",
					admin,
				],
				{
					cwd: new URL("..", import.meta.url),
					env: { ...process.env, CANONICAL_DEPLOYER_PRIVATE_KEY: "" },
				},
			);
			assert.fail("placeholder must block public deployment");
		} catch (error) {
			assert.ok(
				error &&
					typeof error === "object" &&
					"stdout" in error &&
					"code" in error,
			);
			assert.equal(error.code, 1);
			if (DEPLOYER_IS_PLACEHOLDER)
				assert.match(
					String(error.stdout),
					/Canonical deployer is still the placeholder/,
				);
			assert.doesNotMatch(
				String(error.stdout),
				/Fund 0x000000000000000000000000000000000000dEaD/,
			);
			assert.ok(methods.length > 1);
			assert.ok(
				methods.every((method) =>
					["eth_chainId", "eth_getCode", "eth_getBalance"].includes(method),
				),
				methods.join(", "),
			);
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	}
});
