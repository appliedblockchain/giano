/**
 * The argument rules `provision:paymaster` applies before its first transaction (deploy/provision-rules.ts),
 * mainnet ones included, so running the script directly enforces them as the wrapper does.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
	IMMEDIATE_ROLES,
	MIN_MAINNET_UNSTAKE_DELAY,
	mainnetRoleProblems,
	unstakeDelaySeconds,
} from "./provision-rules";

const OPERATOR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const holder = (i: number) => `0x${String(i + 1).padStart(40, "0")}`;
const SIX = Object.fromEntries(IMMEDIATE_ROLES.map((r, i) => [r, holder(i)]));

test("off a mainnet, any role topology is the operator's choice", () => {
	assert.deepEqual(
		mainnetRoleProblems({
			mainnet: false,
			grantAllTo: OPERATOR,
			holders: {},
			operator: OPERATOR,
		}),
		[],
	);
	assert.deepEqual(
		mainnetRoleProblems({
			mainnet: false,
			holders: { pauser: OPERATOR, "fee-collector": OPERATOR },
			operator: OPERATOR,
		}),
		[],
	);
});

test("a mainnet needs six distinct holders, none of them the operator key", () => {
	const mainnet = { mainnet: true, operator: OPERATOR };
	assert.deepEqual(mainnetRoleProblems({ ...mainnet, holders: SIX }), []);
	assert.match(
		mainnetRoleProblems({ ...mainnet, grantAllTo: holder(9), holders: {} })[0],
		/--grant-all-to .* a mainnet refuses it/,
	);
	assert.match(
		mainnetRoleProblems({ ...mainnet, holders: { pauser: holder(0) } })[0],
		/missing: --role-holder-signer-admin, --role-holder-param-admin, --role-holder-stake-admin, --role-holder-tenant-admin, --role-holder-fee-collector/,
	);
	// The same holder twice, in any letter case.
	assert.match(
		mainnetRoleProblems({
			...mainnet,
			holders: {
				...SIX,
				"fee-collector": SIX.pauser.toUpperCase().replace("0X", "0x"),
			},
		}).join("; "),
		/is named for pauser, fee-collector/,
	);
	// The operator key holds ROLE_ADMIN until the hand-off.
	assert.match(
		mainnetRoleProblems({
			...mainnet,
			holders: { ...SIX, pauser: OPERATOR.toLowerCase() },
		}).join("; "),
		/is the operator key, which holds ROLE_ADMIN until the hand-off; a mainnet gives pauser to another holder/,
	);
});

test("the unstake delay is a duration, within uint32, and at least a day on a mainnet", () => {
	assert.equal(unstakeDelaySeconds("86400", { mainnet: false }), 86_400);
	assert.equal(unstakeDelaySeconds("1d", { mainnet: true }), 86_400);
	assert.equal(unstakeDelaySeconds("6h", { mainnet: false }), 21_600);
	assert.equal(unstakeDelaySeconds("1", { mainnet: false }), 1);
	assert.throws(
		() => unstakeDelaySeconds("1x", { mainnet: false }),
		/--unstake-delay is not a duration/,
	);
	assert.throws(
		() => unstakeDelaySeconds("0", { mainnet: false }),
		/between 1 second and 4294967295 seconds/,
	);
	assert.throws(
		() => unstakeDelaySeconds("4294967296", { mainnet: false }),
		/between 1 second/,
	);
	assert.throws(
		() => unstakeDelaySeconds("6h", { mainnet: true }),
		new RegExp(
			`at least ${MIN_MAINNET_UNSTAKE_DELAY} seconds \\(1d\\).*ERC-7562`,
		),
	);
});
