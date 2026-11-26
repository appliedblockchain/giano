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
	parseEther,
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

test("one holder per immediate role: the bootstrap key keeps none of them, even after a failed run", {
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

		const provision = (
			overrides: {
				tenant?: string;
				holders?: string[];
				extra?: string[];
				env?: Record<string, string>;
			} = {},
		) =>
			spawnSync(
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
					overrides.tenant ??
						`${TENANT}:${holder("withdraw")}:provision-test:0.01`,
					...(overrides.holders ??
						Object.entries(HOLDERS).flatMap(([flag, [, address]]) => [
							`--role-holder-${flag}`,
							address,
						])),
					...(overrides.extra ?? []),
				],
				{
					cwd: join(import.meta.dirname, ".."),
					env: {
						...process.env,
						RPC_URL: rpc,
						DEPLOYER_PRIVATE_KEY: OPERATOR,
						...overrides.env,
					},
					encoding: "utf8",
				},
			);
		const read = (functionName: string, args: unknown[] = []) =>
			client.readContract({
				address: paymaster,
				abi: gianoPaymasterAbi,
				functionName: functionName as never,
				args: args as never,
			});
		const runRoles = [
			"SIGNER_ADMIN_ROLE",
			"STAKE_ADMIN_ROLE",
			"TENANT_ADMIN_ROLE",
		];
		const operatorHolds = async (roleName: string) =>
			(await read("hasRole", [await read(roleName), operator])) as boolean;

		// A mistyped holder is refused before anything is sent: no ETH spent, no role taken.
		const nonce = await client.getTransactionCount({ address: operator });
		const typo = provision({
			holders: [
				"--role-holder-pauser",
				"0x123",
				"--role-holder-signer-admin",
				HOLDERS["signer-admin"][1],
			],
		});
		assert.notEqual(typo.status, 0);
		assert.match(
			typo.stderr,
			/role holder for pauser is not an address: 0x123/,
		);
		assert.equal(
			await client.getTransactionCount({ address: operator }),
			nonce,
		);

		// So is an unstake delay that is not a duration: before, it failed at addStake, after the
		// signer transaction had gone out (G42 R6).
		const delayTypo = provision({ extra: ["--unstake-delay", "1x"] });
		assert.notEqual(delayTypo.status, 0);
		assert.match(delayTypo.stderr, /--unstake-delay is not a duration.*: 1x/);
		assert.equal(
			await client.getTransactionCount({ address: operator }),
			nonce,
		);

		// A mainnet the chain-id list does not know, named by the wrapper's GIANO_NETWORK, still gets
		// the mainnet rules the script checks itself: here the one-day unstake minimum (#298 review).
		const shortDelay = provision({
			extra: ["--unstake-delay", "6h"],
			env: { GIANO_NETWORK: "mainnet" },
		});
		assert.notEqual(shortDelay.status, 0);
		assert.match(shortDelay.stderr, /on a mainnet is at least 86400 seconds/);
		assert.equal(
			await client.getTransactionCount({ address: operator }),
			nonce,
		);

		// --plan runs the checks before the first transaction, lists what the run would send, and sends
		// nothing (G48 R3).
		const literal = (text: string) =>
			text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		const planned = provision({ extra: ["--plan"] });
		assert.equal(planned.status, 0, `${planned.stdout}\n${planned.stderr}`);
		for (const action of [
			"take SIGNER_ADMIN_ROLE for this provisioning run",
			`authorise sponsorship signer ${SIGNER}`,
			"stake 0.1 ETH with a 86400s unstake delay",
			`register tenant provision-test (${TENANT})`,
			"fund provision-test with 0.01 ETH",
			`grant PAUSER_ROLE to ${HOLDERS.pauser[1]}`,
			`give up SIGNER_ADMIN_ROLE (held by ${HOLDERS["signer-admin"][1]})`,
		])
			assert.match(planned.stdout, new RegExp(`→ would ${literal(action)}`));
		assert.match(planned.stdout, /carrying 0\.11 ETH plus gas/);
		assert.match(planned.stdout, /Nothing was sent/);
		assert.equal(
			await client.getTransactionCount({ address: operator }),
			nonce,
		);
		for (const roleName of runRoles)
			assert.equal(await operatorHolds(roleName), false, `took ${roleName}`);

		// A plan checks the arguments as a run does.
		const plannedTypo = provision({
			holders: ["--role-holder-pauser", "0x123"],
			extra: ["--plan"],
		});
		assert.notEqual(plannedTypo.status, 0);
		assert.match(
			plannedTypo.stderr,
			/role holder for pauser is not an address/,
		);

		// A run role whose named holder is this key: the plan takes it once, as the run does.
		const selfHeld = provision({
			holders: ["--role-holder-signer-admin", operator],
			extra: ["--plan"],
		});
		assert.equal(selfHeld.status, 0, `${selfHeld.stdout}\n${selfHeld.stderr}`);
		assert.match(
			selfHeld.stdout,
			/→ would take SIGNER_ADMIN_ROLE for this provisioning run/,
		);
		assert.doesNotMatch(selfHeld.stdout, /would grant SIGNER_ADMIN_ROLE/);
		assert.equal(
			await client.getTransactionCount({ address: operator }),
			nonce,
		);

		// A repeated signer is authorised once, so the plan counts one addSigner, as the run sends it.
		const twoSigners = provision({
			extra: ["--signer", SIGNER.toLowerCase(), "--plan"],
		});
		assert.equal(
			twoSigners.status,
			0,
			`${twoSigners.stdout}\n${twoSigners.stderr}`,
		);
		assert.equal(
			twoSigners.stdout.match(/→ would authorise sponsorship signer/g)?.length,
			1,
		);

		// A plan for more ETH than the key holds fails, where a run would fail part-way (S8).
		const plannedShort = provision({
			tenant: `${TENANT}:${holder("withdraw")}:provision-test:1000000`,
			extra: ["--plan"],
		});
		assert.notEqual(plannedShort.status, 0, plannedShort.stdout);
		assert.match(plannedShort.stderr, /1000000\.1 ETH it sends, plus gas\)/);
		assert.equal(
			await client.getTransactionCount({ address: operator }),
			nonce,
		);

		// The check counts gas too: a key that holds exactly the ETH the run sends cannot pay for gas.
		const balance = await client.getBalance({ address: operator });
		const setBalance = (value: bigint) =>
			testClient.setBalance({ address: operator, value });
		await setBalance(parseEther("0.11"));
		try {
			const noGas = provision({ extra: ["--plan"] });
			assert.notEqual(noGas.status, 0, noGas.stdout);
			assert.match(noGas.stdout, /Gas: up to \S+ ETH/);
			assert.match(noGas.stderr, /0\.11 ETH it sends, plus gas\)/);
		} finally {
			await setBalance(balance);
		}

		// A run that fails part-way (a tenant funded with more ETH than the key holds) still gives up
		// the roles it took for the run.
		const broke = provision({
			tenant: `${TENANT}:${holder("withdraw")}:provision-test:1000000`,
		});
		assert.notEqual(broke.status, 0, broke.stdout);
		assert.match(broke.stdout, /stopped part-way/);
		for (const roleName of runRoles)
			assert.equal(await operatorHolds(roleName), false, `kept ${roleName}`);

		// A run killed before it could clean up leaves a role behind; the rerun gives it up anyway,
		// because what is revoked follows the end state, not what the rerun itself granted.
		const operatorClient = createWalletClient({
			chain,
			transport,
			account: privateKeyToAccount(OPERATOR),
		});
		await client.waitForTransactionReceipt({
			hash: await operatorClient.writeContract({
				address: paymaster,
				abi: gianoPaymasterAbi,
				functionName: "grantRole",
				args: [(await read("SIGNER_ADMIN_ROLE")) as `0x${string}`, operator],
			}),
		});
		assert.equal(await operatorHolds("SIGNER_ADMIN_ROLE"), true);

		const run = provision();
		assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);

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
