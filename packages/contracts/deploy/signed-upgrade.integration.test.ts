/**
 * `deploy:cli upgrade --execute --signed-rpc` on a throwaway local anvil, behind a proxy that records
 * every request: the deployer key signs the deployer's requests, and the upgrader key signs the
 * upgrader's own, so a Silent Data RPC keeps the upgrader as `from` on the upgradeToAndCall estimate.
 */
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import {
	type Address,
	createPublicClient,
	createTestClient,
	createWalletClient,
	defineChain,
	getAddress,
	type Hex,
	http,
	keccak256,
	type PublicClient,
	recoverMessageAddress,
	toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { IMPLEMENTATION_SLOT, implementationFromSlot } from "../erc1967";
import { gianoPaymasterAbi } from "../generated";
import { DEPLOYERS, ENTRY_POINT_V09 } from "./config";
import { type DeployContext, deployCore } from "./deploy";
import { impersonate, installCreateX, installEntryPoint } from "./local";
import { loadProfile, paymasterParams } from "./profiles";
import { readRecord, writeRecord } from "./records";
import { loadRelease } from "./release";

const key = (name: string) => keccak256(toHex(`giano-signed-upgrade:${name}`));
/** ROLE_ADMIN from the deployment; it grants itself UPGRADER_ROLE. */
const UPGRADER = key("upgrader");
/** Another key: it deploys the upgrade target, and must not sign the upgrader's requests. */
const DEPLOYER = key("deployer");
const upgrader = privateKeyToAccount(UPGRADER).address;
const deployer = privateKeyToAccount(DEPLOYER).address;

type Received = { body: string; headers: Record<string, unknown> };

async function implementation(client: PublicClient, proxy: Address) {
	return implementationFromSlot(
		await client.getStorageAt({ address: proxy, slot: IMPLEMENTATION_SLOT }),
	);
}

async function freePort(): Promise<number> {
	const socket = createServer();
	await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
	const port = (socket.address() as { port: number }).port;
	await new Promise<void>((resolve) => socket.close(() => resolve()));
	return port;
}

test("upgrade --execute --signed-rpc signs the upgrader's requests with UPGRADER_PRIVATE_KEY", {
	timeout: 120000,
}, async () => {
	const port = await freePort();
	const anvil = spawn(
		"anvil",
		["--host", "127.0.0.1", "--port", String(port), "--silent"],
		{ stdio: "ignore" },
	);
	const dir = mkdtempSync(join(tmpdir(), "giano-signed-upgrade-"));
	const received: Received[] = [];
	const rpc = `http://127.0.0.1:${port}`;
	// Records each request's exact body and headers, then forwards it to anvil.
	const proxy = createHttpServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		received.push({ body, headers: { ...req.headers } });
		const answer = await fetch(rpc, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body,
		});
		res.setHeader("Content-Type", "application/json");
		res.end(await answer.text());
	});
	await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
	const proxyUrl = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
	try {
		const chain = defineChain({
			id: 31337,
			name: "signed upgrade test",
			nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
			rpcUrls: { default: { http: [rpc] } },
		});
		const transport = http(rpc, { retryCount: 0 });
		const client = createPublicClient({ chain, transport }) as PublicClient;
		for (let i = 0; ; i++) {
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
		await installEntryPoint(client, testClient, DEPLOYERS.local, log);
		await impersonate(testClient, DEPLOYERS.local);
		for (const address of [upgrader, deployer])
			await testClient.setBalance({ address, value: 10n ** 20n });
		const record = readRecord(31337, DEPLOYERS.local, dir);
		const ctx: DeployContext = {
			publicClient: client,
			walletClient: createWalletClient({
				chain,
				transport,
				account: DEPLOYERS.local,
			}),
			deployer: DEPLOYERS.local,
			network: "local",
			record,
			log,
		};
		await deployCore(ctx, loadRelease("v3"), {
			entryPoint: ENTRY_POINT_V09,
			roleAdmin: upgrader,
			...paymasterParams(loadProfile({ chain: "base-sepolia" }).profile),
		});
		writeRecord(record, dir);
		const paymaster = record.contracts.paymasterProxy?.address as Address;
		const upgraderRole = await client.readContract({
			address: paymaster,
			abi: gianoPaymasterAbi,
			functionName: "UPGRADER_ROLE",
		});
		await client.waitForTransactionReceipt({
			hash: await createWalletClient({
				chain,
				transport,
				account: privateKeyToAccount(UPGRADER),
			}).writeContract({
				address: paymaster,
				abi: gianoPaymasterAbi,
				functionName: "grantRole",
				args: [upgraderRole, upgrader],
			}),
		});
		const before = await implementation(client, paymaster);

		const run = await promisify(execFile)(
			process.execPath,
			[
				"--import",
				"tsx",
				"deploy/cli.ts",
				"upgrade",
				"--rpc",
				proxyUrl,
				"--contract",
				"paymaster",
				"--release",
				"v3",
				"--record-dir",
				dir,
				"--execute",
				"--signed-rpc",
			],
			{
				cwd: join(import.meta.dirname, ".."),
				env: {
					PATH: process.env.PATH,
					HOME: process.env.HOME,
					DEPLOYER_PRIVATE_KEY: DEPLOYER,
					UPGRADER_PRIVATE_KEY: UPGRADER,
				},
			},
		).catch((error: { stdout: string; stderr: string }) => {
			assert.fail(`upgrade failed:\n${error.stdout}\n${error.stderr}`);
		});
		assert.match(run.stdout, /Upgraded /);

		const after = await implementation(client, paymaster);
		assert.notEqual(after, before);
		assert.equal(
			after && getAddress(after),
			getAddress(readRecord(31337, DEPLOYERS.local, dir).upgrades[0].address),
		);

		// The signature covers the chain id, so only the first eth_chainId goes unsigned.
		const [first, ...rest] = received;
		assert.equal(JSON.parse(first.body).method, "eth_chainId");
		const signers = await Promise.all(
			rest.map(({ body, headers }) =>
				recoverMessageAddress({
					message: `31337${body}${headers["x-timestamp"]}`,
					signature: headers["x-signature"] as Hex,
				}),
			),
		);
		for (const signer of signers)
			assert.ok([upgrader, deployer].includes(signer), signer);
		// Every request sent from the upgrader, the upgradeToAndCall estimate among them, is the
		// upgrader's own; the deployer's sends are the deployer's.
		const from = (body: string) => {
			const params = JSON.parse(body).params?.[0];
			return typeof params?.from === "string"
				? getAddress(params.from)
				: undefined;
		};
		const sentFrom = rest.map(({ body }, i) => ({
			method: JSON.parse(body).method as string,
			from: from(body),
			signer: signers[i],
		}));
		const upgraderSends = sentFrom.filter(({ from }) => from === upgrader);
		// viem estimates with eth_fillTransaction, or eth_estimateGas where the node lacks it.
		assert.ok(
			upgraderSends.some(({ method }) =>
				["eth_fillTransaction", "eth_estimateGas"].includes(method),
			),
			"the upgradeToAndCall estimate",
		);
		for (const { method, signer } of upgraderSends)
			assert.equal(signer, upgrader, method);
		for (const { method, signer } of sentFrom.filter(
			({ from }) => from === deployer,
		))
			assert.equal(signer, deployer, method);
	} finally {
		anvil.kill();
		await new Promise<void>((resolve) => proxy.close(() => resolve()));
		rmSync(dir, { recursive: true, force: true });
	}
});
