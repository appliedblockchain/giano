/** The amounts `pnpm contracts:funding` suggests (G48 R2). */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseEther, parseGwei } from "viem";
import {
	type FundingInputs,
	fundingSuggestions,
	GAS_BUDGET,
	GAS_PRICE_HEADROOM,
	tenantCount,
} from "./funding";

const INPUTS: FundingInputs = {
	stakeEth: "0.1",
	tenantFundEth: "0.02",
	tenantCount: 2,
	minDeployerBalanceEth: "0.05",
	gasPrice: 1_000_251n, // iron-kestrel, 19 November 2026: about 0.001 gwei
	chargesNoGas: false,
};

test("the stake and the tenant balances are fixed; the gas part follows the gas price", () => {
	const cheap = fundingSuggestions(INPUTS);
	// 0.1 + 2 × 0.02, plus 6M gas at 2 × 0.001000251 gwei = 0.000012003 ETH, rounded up to 0.000013.
	assert.equal(cheap.operator.wei, parseEther("0.140013"));
	// 20M gas at 2 × 0.001000251 gwei = 0.00004001 ETH, rounded up.
	assert.equal(cheap.bundlerExecutor.wei, parseEther("0.000041"));

	const dear = fundingSuggestions({ ...INPUTS, gasPrice: parseGwei("1") });
	assert.equal(
		dear.operator.wei,
		parseEther("0.14") +
			GAS_BUDGET.operator * parseGwei("1") * GAS_PRICE_HEADROOM,
	);
	assert.equal(dear.bundlerExecutor.wei, parseEther("0.04"));
	assert.match(
		dear.operator.note,
		/stake 0\.1 \+ 2 tenant balance\(s\) × 0\.02/,
	);
});

test("the canonical deployer gets the profile's reserve, which contracts:deploy requires", () => {
	for (const gasPrice of [1n, parseGwei("50")])
		assert.equal(
			fundingSuggestions({ ...INPUTS, gasPrice }).canonicalDeployer.wei,
			parseEther("0.05"),
		);
});

test("a chain that charges nothing for gas needs ETH only for the stake and the tenant balances", () => {
	const free = fundingSuggestions({
		...INPUTS,
		gasPrice: 0n,
		chargesNoGas: true,
	});
	assert.equal(free.operator.wei, parseEther("0.14"));
	assert.equal(free.bundlerExecutor.wei, "none");
	assert.equal(free.canonicalDeployer.wei, "none");
});

test("an unknown gas price leaves the gas part out and says so", () => {
	const unknown = fundingSuggestions({ ...INPUTS, gasPrice: undefined });
	assert.equal(unknown.operator.wei, parseEther("0.14"));
	assert.match(unknown.operator.note, /gas price could not be read/);
	assert.equal(unknown.bundlerExecutor.wei, "unknown");
	assert.equal(unknown.canonicalDeployer.wei, parseEther("0.05"));
});

test("a gas price of 0 on a chain that still charges for gas leaves the gas part out, not at 0", () => {
	// An OP Stack chain with no L2 gas price but an L1 data fee: the executor pays that fee.
	const l1Fee = fundingSuggestions({
		...INPUTS,
		gasPrice: 0n,
		chargesNoGas: false,
	});
	assert.equal(l1Fee.operator.wei, parseEther("0.14"));
	assert.match(
		l1Fee.operator.note,
		/the gas price is 0, but the chain still charges/,
	);
	assert.equal(l1Fee.bundlerExecutor.wei, "unknown");
	assert.equal(l1Fee.canonicalDeployer.wei, parseEther("0.05"));
});

test("an amount that is not ETH is named", () => {
	assert.throws(
		() => fundingSuggestions({ ...INPUTS, stakeEth: "lots" }),
		/STAKE_ETH is not an ETH amount: lots/,
	);
});

test("tenants are counted from PAYMASTER_TENANTS", () => {
	assert.equal(tenantCount(undefined), 0);
	assert.equal(tenantCount(""), 0);
	assert.equal(tenantCount("example:1111, byoui:2222 ,"), 2);
});
