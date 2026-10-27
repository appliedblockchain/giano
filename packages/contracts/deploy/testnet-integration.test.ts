/** Runs real committed release transactions on a throwaway local anvil, never a public RPC. */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import {
	createPublicClient,
	createTestClient,
	createWalletClient,
	defineChain,
	http,
	type PublicClient,
} from "viem";
import { CANONICAL_DEPLOYER, ENTRY_POINT_V07 } from "./config";
import { type DeployContext, deployCore } from "./deploy";
import { impersonate, installCreateX, installEntryPoint } from "./local";
import { readRecord, writeRecord } from "./records";
import { loadRelease } from "./release";
import { inspectTestnet, PAYMASTER_DEFAULTS } from "./testnet-checks";

test("real CREATE3 release deploy, interrupted checkpoint recovery, verification and idempotent rerun", {
	timeout: 90000,
}, async () => {
	const socket = createServer();
	await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
	const address = socket.address();
	assert.ok(address && typeof address !== "string");
	await new Promise<void>((resolve) => socket.close(() => resolve()));
	const anvil = spawn(
		"anvil",
		[
			"--host",
			"127.0.0.1",
			"--port",
			String(address.port),
			"--chain-id",
			"84532",
			"--silent",
		],
		{ stdio: "ignore" },
	);
	let spawnError: Error | undefined;
	anvil.on("error", (error) => {
		spawnError = error;
	});
	const dir = mkdtempSync(join(tmpdir(), "giano-testnet-"));
	try {
		const rpc = `http://127.0.0.1:${address.port}`;
		const chain = defineChain({
			id: 84532,
			name: "isolated test",
			nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
			rpcUrls: { default: { http: [rpc] } },
		});
		const transport = http(rpc, { retryCount: 0 });
		const client = createPublicClient({ chain, transport }) as PublicClient;
		for (let i = 0; ; i++) {
			if (spawnError) throw spawnError;
			try {
				await client.getChainId();
				break;
			} catch (error) {
				if (i >= 50) throw error;
				await delay(100);
			}
		}
		const testClient = createTestClient({ chain, transport, mode: "anvil" });
		const log = () => {};
		await installCreateX(client, testClient, log);
		await installEntryPoint(client, testClient, CANONICAL_DEPLOYER, log);
		await impersonate(testClient, CANONICAL_DEPLOYER);
		const walletClient = createWalletClient({
			chain,
			transport,
			account: CANONICAL_DEPLOYER,
		});
		const record = readRecord(84532, CANONICAL_DEPLOYER, dir);
		let checkpoints = 0;
		const ctx: DeployContext = {
			publicClient: client,
			walletClient,
			deployer: CANONICAL_DEPLOYER,
			record,
			log,
			onRecord: () => {
				writeRecord(record, dir);
				if (++checkpoints === 2) throw new Error("test interruption");
			},
		};
		const params = {
			entryPoint: ENTRY_POINT_V07,
			roleAdmin: CANONICAL_DEPLOYER,
			...PAYMASTER_DEFAULTS,
		};
		await assert.rejects(
			deployCore(ctx, loadRelease("v1"), params),
			/test interruption/,
		);
		const interrupted = readRecord(84532, CANONICAL_DEPLOYER, dir);
		assert.equal(Object.keys(interrupted.contracts).length, 2);
		const firstHash = interrupted.contracts.factory?.transactionHash;
		assert.ok(firstHash);
		ctx.record = interrupted;
		ctx.onRecord = () => {
			writeRecord(ctx.record, dir);
		};
		await deployCore(ctx, loadRelease("v1"), params);
		assert.equal(ctx.record.contracts.factory?.transactionHash, firstHash);
		assert.equal(Object.keys(ctx.record.contracts).length, 4);
		const checks = await inspectTestnet(
			client,
			"base-sepolia",
			"v1",
			CANONICAL_DEPLOYER,
		);
		assert.deepEqual(
			checks.filter((check) => !check.ok),
			[],
		);
		const before = readFileSync(join(dir, "84532.json"), "utf8");
		const nonceBefore = await client.getTransactionCount({
			address: CANONICAL_DEPLOYER,
		});
		await deployCore(ctx, loadRelease("v1"), params);
		assert.equal(
			await client.getTransactionCount({ address: CANONICAL_DEPLOYER }),
			nonceBefore,
		);
		assert.equal(readFileSync(join(dir, "84532.json"), "utf8"), before);
	} finally {
		anvil.kill();
		rmSync(dir, { recursive: true, force: true });
	}
});
