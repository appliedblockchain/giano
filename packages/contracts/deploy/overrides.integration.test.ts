/**
 * Adopting a chain with address overrides, on a throwaway local anvil (openspec: contract-deployment,
 * "Profiles can override contract addresses"). A first key deploys the core contracts; a second
 * class deployer then adopts the chain with that wallet implementation and paymaster proxy
 * overridden: they are verified and reused, the factory is deployed at the class's deterministic
 * address and bound to the overridden implementation, and the record says which is which.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
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
	type PublicClient,
} from "viem";
import { gianoSmartWalletFactoryAbi } from "../generated";
import { releaseOf } from "../release-code";
import { ENTRY_POINT_V09, LABELS } from "./config";
import { create3Address } from "./create3";
import { type DeployContext, deployCore } from "./deploy";
import { impersonate, installCreateX, installEntryPoint } from "./local";
import { fixedAddresses, planCore } from "./plan";
import { profileCoreConfig, verifyCoreState } from "./preflight";
import { loadProfile, paymasterParams } from "./profiles";
import { recordDeviations } from "./records";
import { loadRelease } from "./release";

const profile = loadProfile({ chain: "base-sepolia" }).profile;
const EARLIER_KEY = getAddress("0x00000000000000000000000000000000000E4211");
const CLASS_DEPLOYER = getAddress("0x00000000000000000000000000000000000C1A55");

test("overridden wallet implementation and paymaster are verified and reused, dependants wired to them", {
	timeout: 90000,
}, async () => {
	const socket = createServer();
	await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
	const port = (socket.address() as { port: number }).port;
	await new Promise<void>((resolve) => socket.close(() => resolve()));
	const anvil = spawn(
		"anvil",
		[
			"--host",
			"127.0.0.1",
			"--port",
			String(port),
			"--chain-id",
			"84532",
			"--silent",
		],
		{ stdio: "ignore" },
	);
	try {
		const rpc = `http://127.0.0.1:${port}`;
		const chain = defineChain({
			id: 84532,
			name: "isolated test",
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
		await installEntryPoint(client, testClient, EARLIER_KEY, log);
		const params = {
			entryPoint: ENTRY_POINT_V09,
			roleAdmin: EARLIER_KEY,
			...paymasterParams(profile),
		};
		const context = (signer: Address): DeployContext => ({
			publicClient: client,
			walletClient: createWalletClient({ chain, transport, account: signer }),
			deployer: signer,
			network: "testnet",
			classDeployer: CLASS_DEPLOYER,
			record: { chainId: 84532, deployer: signer, contracts: {}, upgrades: [] },
			log,
		});

		// Contracts that already exist on the chain, deployed by another key.
		await impersonate(testClient, EARLIER_KEY);
		const earlier = context(EARLIER_KEY);
		await deployCore(earlier, loadRelease("v2"), params);
		const wallet = earlier.record.contracts.walletImplementation?.address;
		const proxy = earlier.record.contracts.paymasterProxy?.address;
		const paymaster = earlier.record.contracts.paymasterImplementation?.address;
		assert.ok(wallet && proxy && paymaster);

		// Overriding the proxy alone is refused: it points at the earlier key's implementation, not
		// at the one the class deployer would deploy.
		const proxyOnly = await planCore(client, {
			network: "testnet",
			signer: CLASS_DEPLOYER,
			deployer: CLASS_DEPLOYER,
			overrides: { walletImplementation: wallet, paymasterProxy: proxy },
			release: "v2",
		});
		assert.match(
			proxyOnly.blockers.join("\n"),
			new RegExp(`Override paymasterImplementation with ${paymaster}`),
		);

		// The class deployer adopts the chain with the wallet implementation and the paymaster
		// (proxy and implementation) overridden.
		await impersonate(testClient, CLASS_DEPLOYER);
		const overrides = {
			walletImplementation: wallet,
			paymasterImplementation: paymaster,
			paymasterProxy: proxy,
		};
		const plan = await planCore(client, {
			network: "testnet",
			signer: CLASS_DEPLOYER,
			deployer: CLASS_DEPLOYER,
			overrides,
			release: "v2",
		});
		assert.deepEqual(plan.blockers, []);
		assert.deepEqual(
			plan.deviations.map((d) => [d.key, d.reason, d.actual]),
			[
				["walletImplementation", "override", wallet],
				["paymasterImplementation", "override", paymaster],
				["paymasterProxy", "override", proxy],
			],
		);
		const nonceBefore = await client.getTransactionCount({
			address: CLASS_DEPLOYER,
		});
		const ctx = context(CLASS_DEPLOYER);
		await deployCore(ctx, loadRelease("v2"), params, fixedAddresses(plan));
		recordDeviations(ctx.record, plan.deviations, false);

		// One transaction: the factory. The overrides are reused.
		assert.equal(
			(await client.getTransactionCount({ address: CLASS_DEPLOYER })) -
				nonceBefore,
			1,
		);
		const { contracts } = ctx.record;
		assert.equal(contracts.walletImplementation?.address, wallet);
		assert.equal(contracts.paymasterProxy?.address, proxy);
		assert.equal(contracts.walletImplementation?.deterministic, false);
		assert.equal(contracts.paymasterProxy?.deterministic, false);
		const factory = create3Address(CLASS_DEPLOYER, LABELS.factory);
		assert.equal(contracts.factory?.address, factory);
		assert.equal(contracts.factory?.deterministic, true);
		assert.ok(contracts.factory?.transactionHash);
		assert.equal(
			await client.readContract({
				address: factory,
				abi: gianoSmartWalletFactoryAbi,
				functionName: "implementation",
			}),
			wallet,
		);
		const factoryCode = await client.getCode({ address: factory });
		assert.equal(
			releaseOf("GianoSmartWalletFactory", factoryCode ?? "0x", factory)
				?.release,
			"v2",
		);
		assert.deepEqual(
			ctx.record.deviations?.map((d) => [d.contract, d.reason, d.confirmed]),
			[
				["walletImplementation", "override", false],
				["paymasterImplementation", "override", false],
				["paymasterProxy", "override", false],
			],
		);
		// The re-plan after deployment is clean, and the overridden proxy's configuration checks out.
		const after = await planCore(client, {
			network: "testnet",
			signer: CLASS_DEPLOYER,
			deployer: CLASS_DEPLOYER,
			overrides,
			record: ctx.record,
		});
		assert.deepEqual(after.blockers, []);
		await verifyCoreState(
			client,
			EARLIER_KEY,
			profileCoreConfig(profile),
			after,
		);
	} finally {
		anvil.kill();
	}
});
