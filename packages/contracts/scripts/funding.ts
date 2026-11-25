/**
 * Prints the accounts to fund with testnet ETH, derived from the keys in the selected operator
 * environment, their balances, and the suggested amounts (deploy/funding.ts). Run by
 * `pnpm contracts:funding`, through deploy/contracts/print-funding.sh. Reads only.
 *
 * Environment: RPC_URL, CHAIN_ID, CHAIN_NAME, DEPLOYER_MIN_ETH (the launcher sets these), and from
 * the operator environment the keys, STAKE_ETH, TENANT_FUND_ETH and PAYMASTER_TENANTS.
 */
import {
	type Address,
	createPublicClient,
	formatEther,
	formatGwei,
	http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
	fundingSuggestions,
	GAS_PRICE_HEADROOM,
	type Suggestion,
	tenantCount,
} from "../deploy/funding";
import { chargesNoGas } from "../gasless";

async function main(): Promise<void> {
	const env = process.env;
	const client = createPublicClient({ transport: http(env.RPC_URL) });

	let gasPrice: bigint | undefined;
	let gasless = false;
	try {
		gasPrice = await client.getGasPrice();
		// A gas price above 0 already answers it; only a 0 needs the full check (gasless.ts).
		gasless = gasPrice === 0n && (await chargesNoGas(client));
	} catch {
		gasPrice = undefined;
	}
	const suggestions = fundingSuggestions({
		stakeEth: env.STAKE_ETH || "0.1",
		tenantFundEth: env.TENANT_FUND_ETH || "0.02",
		tenantCount: tenantCount(env.PAYMASTER_TENANTS),
		minDeployerBalanceEth: env.DEPLOYER_MIN_ETH || "0",
		gasPrice,
		chargesNoGas: gasless,
	});

	console.log(`\nNetwork: ${env.CHAIN_NAME} (${env.CHAIN_ID})`);
	console.log(
		gasless
			? "Gas price: 0. The chain charges nothing for gas.\n"
			: gasPrice === undefined
				? "Gas price: could not be read. The suggestions below leave out gas.\n"
				: gasPrice === 0n
					? "Gas price: 0, but the chain still charges for gas (on OP Stack, the L1 data fee). The suggestions below leave out gas.\n"
					: `Gas price: ${formatGwei(gasPrice)} gwei. Gas is budgeted at ${GAS_PRICE_HEADROOM}× this price; on an OP Stack chain the L1 data fee comes on top.\n`,
	);

	const rows: [string, string | undefined, Suggestion][] = [
		[
			"Canonical deployer",
			env.CANONICAL_DEPLOYER_PRIVATE_KEY,
			suggestions.canonicalDeployer,
		],
		["Operator", env.DEPLOYER_PRIVATE_KEY, suggestions.operator],
		[
			"Bundler executor",
			(env.BUNDLER_EXECUTOR_PRIVATE_KEYS || "").split(",")[0].trim(),
			suggestions.bundlerExecutor,
		],
		// Listed so a missing key is caught here rather than three steps later, not because it needs
		// ETH: it authorises spending against the tenant's paymaster balance and never pays gas.
		[
			"Sponsorship signer",
			env.SPONSORSHIP_SIGNER_KEY,
			{ wei: "none", note: "signs ERC-7677 sponsorships — no funding needed" },
		],
	];
	for (const [name, key, suggestion] of rows) {
		if (!key) {
			console.log(
				`${name.padEnd(20)} <key not set in the selected operator environment>`,
			);
			continue;
		}
		let address: Address;
		try {
			// ethers, which the workflows use, also takes a key without 0x.
			const hex = key.startsWith("0x") ? key : `0x${key}`;
			address = privateKeyToAccount(hex as `0x${string}`).address;
		} catch {
			console.log(`${name}: invalid key; correct the operator environment.`);
			process.exitCode = 1;
			continue;
		}
		let balance = "?";
		try {
			balance = formatEther(await client.getBalance({ address }));
		} catch {}
		const want =
			typeof suggestion.wei === "bigint"
				? `${formatEther(suggestion.wei)} ETH`
				: suggestion.wei;
		console.log(`${name.padEnd(20)} ${address}`);
		console.log(
			`${"".padEnd(20)} balance: ${balance} ETH   suggested: ${want}   (${suggestion.note})\n`,
		);
	}
	console.log(
		"Fund these addresses on the selected network; balances and fees do not carry across chains.",
	);
}

main().catch((error: unknown) => {
	// Only a message about an amount. A provider error can quote the RPC URL, and its token.
	const message = error instanceof Error ? error.message : "";
	console.error(
		/^\S+ is not an ETH amount: /.test(message)
			? message
			: "contracts:funding stopped. Check the operator environment and RPC access.",
	);
	process.exitCode = 1;
});
