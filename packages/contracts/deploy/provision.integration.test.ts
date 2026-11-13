/**
 * Provisioning with one holder per immediate role (scripts/provision-paymaster.ts) on a throwaway local
 * anvil: the bootstrap key authorises the signer, stakes and registers the tenant with roles it holds
 * only for the run, then hands every role to its holder and keeps none of them.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import {
	type Address,
	createPublicClient,
	createTestClient,
	createWalletClient,
	defineChain,
	getAddress,
	http,
	keccak256,
	type PublicClient,
	toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gianoPaymasterAbi } from "../generated";
import { DEPLOYERS, ENTRY_POINT_V09 } from "./config";
import { type DeployContext, deployCore } from "./deploy";
import { impersonate, installCreateX, installEntryPoint } from "./local";
import { loadProfile, paymasterParams } from "./profiles";
import { readRecord } from "./records";
import { loadRelease } from "./release";

const key = (role: string) => keccak256(toHex(`giano-provision-test:${role}`));
const OPERATOR = key("operator");
const operator = privateKeyToAccount(OPERATOR).address;
const holder = (role: string): Address =>
	privateKeyToAccount(key(role)).address;
const HOLDERS = {
	"signer-admin": ["SIGNER_ADMIN_ROLE", holder("signer-admin")],
	"param-admin": ["PARAM_ADMIN_ROLE", holder("param-admin")],
	pauser: ["PAUSER_ROLE", holder("pauser")],
	"stake-admin": ["STAKE_ADMIN_ROLE", holder("stake-admin")],
	"tenant-admin": ["TENANT_ADMIN_ROLE", holder("tenant-admin")],
	"fee-collector": ["FEE_COLLECTOR_ROLE", holder("fee-collector")],
} as const;
const SIGNER = holder("sponsorship-signer");
const TENANT = "44444444-4444-4444-8444-444444444444";

test("one holder per immediate role: the bootstrap key keeps none of them", {
	timeout: 120000,
}, async () => {
	const socket = createServer();
	await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
	const port = (socket.address() as { port: number }).port;
	await new Promise<void>((resolve) => socket.close(() => resolve()));
	const anvil = spawn(
		"anvil",
		["--host", "127.0.0.1", "--port", String(port), "--silent"],
		{ stdio: "ignore" },
	);
	const dir = mkdtempSync(join(tmpdir(), "giano-provision-"));
	try {
		const rpc = `http://127.0.0.1:${port}`;
		const chain = defineChain({
			id: 31337,
			name: "provision test",
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
		await testClient.setBalance({ address: operator, value: 10n ** 20n });
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
			roleAdmin: operator,
			...paymasterParams(loadProfile({ chain: "base-sepolia" }).profile),
		});
		const paymaster = record.contracts.paymasterProxy?.address as Address;

		const run = spawnSync(
			process.execPath,
			[
				"--import",
				"tsx",
				"scripts/provision-paymaster.ts",
				"--paymaster",
				paymaster,
				"--signer",
				SIGNER,
				"--stake-eth",
				"0.1",
				"--tenant",
				`${TENANT}:${holder("withdraw")}:provision-test:0.01`,
				...Object.entries(HOLDERS).flatMap(([flag, [, address]]) => [
					`--role-holder-${flag}`,
					address,
				]),
			],
			{
				cwd: join(import.meta.dirname, ".."),
				env: { ...process.env, RPC_URL: rpc, DEPLOYER_PRIVATE_KEY: OPERATOR },
				encoding: "utf8",
			},
		);
		assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);

		const read = (functionName: string, args: unknown[] = []) =>
			client.readContract({
				address: paymaster,
				abi: gianoPaymasterAbi,
				functionName: functionName as never,
				args: args as never,
			});
		for (const [roleName, address] of Object.values(HOLDERS)) {
			const role = (await read(roleName)) as `0x${string}`;
			assert.equal(await read("hasRole", [role, address]), true, `${roleName}`);
			assert.equal(
				await read("hasRole", [role, operator]),
				false,
				`the bootstrap key kept ${roleName}`,
			);
		}
		// The bootstrap key keeps the timelocked roles, ROLE_ADMIN included, until contracts:handoff.
		for (const roleName of [
			"UPGRADER_ROLE",
			"FEE_ADMIN_ROLE",
			"WITHDRAW_ADDRESS_ADMIN_ROLE",
		])
			assert.equal(
				await read("hasRole", [await read(roleName), operator]),
				true,
				roleName,
			);
		assert.equal(
			await read("hasRole", [await read("ROLE_ADMIN"), operator]),
			true,
		);
		assert.equal(await read("isSigner", [SIGNER]), true);
		const tenant = (await read("getTenant", [
			`0x${TENANT.replaceAll("-", "")}`,
		])) as { registered: boolean; withdrawAddress: Address };
		assert.equal(tenant.registered, true);
		assert.equal(getAddress(tenant.withdrawAddress), holder("withdraw"));
	} finally {
		anvil.kill();
		rmSync(dir, { recursive: true, force: true });
	}
});
