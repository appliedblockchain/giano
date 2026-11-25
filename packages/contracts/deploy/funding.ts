/**
 * The ETH `pnpm contracts:funding` suggests for each operator account (G48 R2).
 *
 * Each suggestion has a fixed part and a gas part. The fixed part is ETH the account sends away and
 * gets back only later: the paymaster's EntryPoint stake and the tenant balances. The gas part is a
 * gas budget priced at the chain's gas price, with headroom. Before, every amount was fixed, and the
 * suggestions totalled 0.35 ETH on a chain where the whole rollout cost about 0.005 ETH (S5).
 */
import { formatEther, parseEther } from "viem";

/**
 * Gas each account spends, in gas units, rounded up. The operator: provisioning (about 15
 * transactions), the GianoTimelock deployment (about 2.5M gas) and the hand-off (8 transactions).
 * The bundler executor: it fronts the gas of every handleOps bundle, and the EntryPoint pays it
 * back, so it needs enough for the bundles in flight, about 40 sponsored operations.
 */
export const GAS_BUDGET = {
	operator: 6_000_000n,
	bundlerExecutor: 20_000_000n,
} as const;

/** The gas price can rise between the suggestion and the transactions: budget at this multiple. */
export const GAS_PRICE_HEADROOM = 2n;

/** Suggestions are rounded up to this unit, 0.000001 ETH, so they stay short to read. */
const ROUNDING_WEI = 10n ** 12n;

export type FundingInputs = {
	/** STAKE_ETH: the paymaster's EntryPoint stake. */
	stakeEth: string;
	/** TENANT_FUND_ETH: the balance provisioning deposits for each tenant. */
	tenantFundEth: string;
	/** The number of tenants in PAYMASTER_TENANTS. */
	tenantCount: number;
	/** The chain profile's minDeployerBalanceEth, which contracts:deploy requires. */
	minDeployerBalanceEth: string;
	/**
	 * eth_gasPrice, or undefined when it could not be read. A 0 with chargesNoGas false (an OP Stack
	 * chain's L1 data fee) cannot price the gas part either, so the gas part is then left out.
	 */
	gasPrice: bigint | undefined;
	/** The chain charges nothing for gas (gasless.ts). */
	chargesNoGas: boolean;
};

export type Suggestion = {
	/** Wei to hold; "none" when the account needs no ETH; "unknown" when the gas price is unknown. */
	wei: bigint | "none" | "unknown";
	/** What the amount is made of. */
	note: string;
};

export type FundingSuggestions = {
	canonicalDeployer: Suggestion;
	operator: Suggestion;
	bundlerExecutor: Suggestion;
};

function roundUp(wei: bigint): bigint {
	return ((wei + ROUNDING_WEI - 1n) / ROUNDING_WEI) * ROUNDING_WEI;
}

function ether(name: string, value: string): bigint {
	try {
		return parseEther(value);
	} catch {
		throw new Error(`${name} is not an ETH amount: ${value}`);
	}
}

/** The suggested balance of each account that pays for something. */
export function fundingSuggestions(input: FundingInputs): FundingSuggestions {
	const stake = ether("STAKE_ETH", input.stakeEth);
	const tenantFund = ether("TENANT_FUND_ETH", input.tenantFundEth);
	const gas = (units: bigint): bigint | undefined =>
		input.chargesNoGas
			? 0n
			: !input.gasPrice
				? undefined
				: roundUp(units * input.gasPrice * GAS_PRICE_HEADROOM);
	const unpriced =
		input.gasPrice === undefined
			? "the gas price could not be read"
			: "the gas price is 0, but the chain still charges for gas (on OP Stack, the L1 data fee)";

	const operatorGas = gas(GAS_BUDGET.operator);
	const tenants = tenantFund * BigInt(input.tenantCount);
	const fixed = `stake ${input.stakeEth} + ${input.tenantCount} tenant balance(s) × ${input.tenantFundEth}`;
	const operator: Suggestion =
		operatorGas === undefined
			? {
					wei: stake + tenants,
					note: `${fixed}, plus gas: ${unpriced}`,
				}
			: {
					wei: stake + tenants + operatorGas,
					note: `${fixed} + ${formatEther(operatorGas)} gas for provisioning, the timelock and the hand-off`,
				};

	const executorGas = gas(GAS_BUDGET.bundlerExecutor);
	const bundlerExecutor: Suggestion = input.chargesNoGas
		? { wei: "none", note: "the chain charges nothing for gas" }
		: {
				wei: executorGas ?? "unknown",
				note:
					executorGas === undefined
						? `fronts gas for every handleOps transaction; ${unpriced}`
						: "fronts gas for every handleOps transaction; the EntryPoint pays it back",
			};

	// contracts:deploy refuses to start below the profile's reserve, whatever the gas price, unless
	// the chain charges nothing for gas (deploy/preflight.ts). So the suggestion is that reserve.
	const canonicalDeployer: Suggestion = input.chargesNoGas
		? { wei: "none", note: "the chain charges nothing for gas" }
		: {
				wei: ether("minDeployerBalanceEth", input.minDeployerBalanceEth),
				note: "core contract deployments: the chain profile's minDeployerBalanceEth, which contracts:deploy requires",
			};

	return { canonicalDeployer, operator, bundlerExecutor };
}

/** The tenants in PAYMASTER_TENANTS (`slug:uuid,slug:uuid`). */
export function tenantCount(paymasterTenants: string | undefined): number {
	return (paymasterTenants ?? "")
		.split(",")
		.filter((pair) => pair.trim() !== "").length;
}
