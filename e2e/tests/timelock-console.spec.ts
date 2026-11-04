import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Page, test } from "@playwright/test";
import {
	type Address,
	createPublicClient,
	createWalletClient,
	defineChain,
	encodeAbiParameters,
	getAddress,
	type Hex,
	http,
	parseAbiParameters,
	zeroAddress,
} from "viem";

import { CHAINS } from "../origins.mjs";
import {
	chooseDeployment,
	installWallet,
	OPERATOR,
	openConsole,
	signInToPaymaster,
	tab,
} from "./console-wallet";

/**
 * The Timelock tab against a real GianoTimelock (openspec redesign-paymaster-console, task 8.7).
 *
 * The e2e devnet's baked state has no timelock, and the rest of the suite needs admin-console to keep
 * every paymaster role, so this file deploys its own: a 2-second GianoTimelock from the v2 release,
 * with admin-console as its proposer and canceller and executors open. The console is pointed at it
 * by adding `timelockAddress` to the /config.json it fetches. The timelock is granted ROLE_ADMIN on
 * the paymaster alongside admin-console, so a role change it executes really lands; that grant, and
 * every role the tests hand out, is taken back afterwards.
 *
 * Two seconds is short enough to wait out in real time: anvil stamps each block with the wall clock,
 * so no time travel is needed — only a block after the delay, which `evm_mine` provides.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const release = JSON.parse(
	fs.readFileSync(
		path.join(
			here,
			"..",
			"..",
			"packages",
			"contracts",
			"releases",
			"v2",
			"release.json",
		),
		"utf8",
	),
) as { contracts: { GianoTimelock: { creationCode: Hex } } };

const chain = defineChain({
	id: CHAINS.a.chainId,
	name: CHAINS.a.name,
	nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
	rpcUrls: { default: { http: [CHAINS.a.rpc] } },
});
const reader = createPublicClient({ chain, transport: http(CHAINS.a.rpc) });
const operator = createWalletClient({
	account: OPERATOR,
	chain,
	transport: http(CHAINS.a.rpc),
});

const ROLE_ABI = [
	{
		type: "function",
		name: "hasRole",
		stateMutability: "view",
		inputs: [{ type: "bytes32" }, { type: "address" }],
		outputs: [{ type: "bool" }],
	},
	{
		type: "function",
		name: "grantRole",
		stateMutability: "nonpayable",
		inputs: [{ type: "bytes32" }, { type: "address" }],
		outputs: [],
	},
	{
		type: "function",
		name: "revokeRole",
		stateMutability: "nonpayable",
		inputs: [{ type: "bytes32" }, { type: "address" }],
		outputs: [],
	},
	{
		type: "function",
		name: "defaultFeeWei",
		stateMutability: "view",
		inputs: [],
		outputs: [{ type: "uint256" }],
	},
] as const;

/** A role's id, as the paymaster defines it: read from its public constant rather than recomputed. */
const roleIds = new Map<string, Hex>();
async function role(name: string): Promise<Hex> {
	const known = roleIds.get(name);
	if (known) return known;
	const id = (await reader.readContract({
		address: paymaster,
		abi: [
			{
				type: "function",
				name,
				stateMutability: "view",
				inputs: [],
				outputs: [{ type: "bytes32" }],
			},
		],
		functionName: name,
	})) as Hex;
	roleIds.set(name, id);
	return id;
}

let paymaster: Address;
let timelock: Address;

async function send(
	functionName: "grantRole" | "revokeRole",
	roleName: string,
	account: Address,
) {
	const hash = await operator.writeContract({
		address: paymaster,
		abi: ROLE_ABI,
		functionName,
		args: [await role(roleName), account],
	});
	const receipt = await reader.waitForTransactionReceipt({ hash });
	if (receipt.status !== "success")
		throw new Error(
			`${functionName} ${roleName} for ${account} reverted (${hash})`,
		);
}

const holds = async (roleName: string, account: Address) =>
	reader.readContract({
		address: paymaster,
		abi: ROLE_ABI,
		functionName: "hasRole",
		args: [await role(roleName), account],
	});

/** Two fresh addresses per run, so nothing a run grants is mistaken for another run's. */
const stamp = Date.now().toString(16);
const OLD_HOLDER =
	`0x${"c1".padEnd(40 - stamp.length, "0")}${stamp}` as Address;
const NEW_HOLDER =
	`0x${"d2".padEnd(40 - stamp.length, "0")}${stamp}` as Address;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
	paymaster = (
		JSON.parse(
			fs.readFileSync(
				path.join(here, "..", "devnet", "addresses.json"),
				"utf8",
			),
		) as Record<string, Address>
	).sponsorshipPaymaster;

	const args = encodeAbiParameters(
		parseAbiParameters(
			"uint256, address[], address[], (address, bytes4, uint256)[]",
		),
		[2n, [OPERATOR], [zeroAddress], []],
	);
	const hash = await operator.sendTransaction({
		data: `${release.contracts.GianoTimelock.creationCode}${args.slice(2)}` as Hex,
	});
	const receipt = await reader.waitForTransactionReceipt({ hash });
	if (!receipt.contractAddress) throw new Error("the timelock did not deploy");
	timelock = receipt.contractAddress;

	// The timelock may change roles only if it is a ROLE_ADMIN; admin-console stays one too.
	await send("grantRole", "ROLE_ADMIN", timelock);
	await send("grantRole", "PAUSER_ROLE", OLD_HOLDER);
});

test.afterAll(async () => {
	for (const account of [OLD_HOLDER, NEW_HOLDER])
		if (await holds("PAUSER_ROLE", account))
			await send("revokeRole", "PAUSER_ROLE", account);
	if (timelock && (await holds("ROLE_ADMIN", timelock)))
		await send("revokeRole", "ROLE_ADMIN", timelock);
});

/**
 * Opens the console on chain A with this file's timelock configured, signed in as admin-console.
 * `timelockDelays` are the published delays Health compares the timelock's with.
 */
async function openWithTimelock(
	page: Page,
	timelockDelays?: Record<string, number>,
) {
	await page.route("**/config.json", async (route) => {
		const response = await route.fetch();
		const json = await response.json();
		for (const deployment of json.deployments)
			if (deployment.chainId === CHAINS.a.chainId) {
				deployment.timelockAddress = timelock;
				if (timelockDelays) deployment.timelockDelays = timelockDelays;
			}
		await route.fulfill({ response, json });
	});
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();
	await signInToPaymaster(page);
	await tab(page, /Timelock/).click();
}

/** Waits out the 2-second delay and mines a block, so the chain agrees the operation is ready. */
async function waitOutTheDelay(page: Page) {
	await page.waitForTimeout(2_500);
	await reader.request({ method: "evm_mine" as never, params: [] as never });
	await page.getByRole("button", { name: "Refresh", exact: true }).click();
}

test("the Timelock tab says who proposes, cancels and executes, and what this wallet may do", async ({
	page,
}) => {
	await openWithTimelock(page);
	await expect(page.getByText("2s").first()).toBeVisible();
	await expect(page.getByText("anyone (open)")).toBeVisible();
	await expect(page.getByText("schedule", { exact: true })).toBeVisible();
	await expect(page.getByText("cancel", { exact: true })).toBeVisible();
	await expect(
		page.getByText(/The timelock cannot list who holds its roles/),
	).toBeVisible();
});

test("a role rotation is proposed as one batch, scheduled by the proposer and executed together", async ({
	page,
}) => {
	await openWithTimelock(page);

	// grant to the new holder, then add the revoke from the old one to the same operation
	await page.getByLabel("Change", { exact: true }).selectOption("grantRole");
	await page.getByLabel("Role", { exact: true }).selectOption("PAUSER_ROLE");
	await page.getByRole("textbox", { name: "Account" }).fill(NEW_HOLDER);
	await page.getByRole("button", { name: "Build proposal" }).click();
	const dialog = page.getByRole("dialog", { name: "Timelock proposal" });
	await expect(dialog.getByTestId("proposal-result")).toBeVisible();
	await dialog.getByRole("button", { name: "Add a call" }).click();
	await dialog.getByLabel("Change", { exact: true }).selectOption("revokeRole");
	await dialog.getByLabel("Role", { exact: true }).selectOption("PAUSER_ROLE");
	await dialog.getByRole("textbox", { name: "Account" }).fill(OLD_HOLDER);
	await dialog.getByRole("button", { name: "Add to this operation" }).click();
	await expect(dialog.getByTestId("proposal-calls")).toContainText(
		"grant PAUSER_ROLE",
	);
	await expect(dialog.getByTestId("proposal-calls")).toContainText(
		"revoke PAUSER_ROLE",
	);
	await expect(dialog.getByTestId("proposal-result")).toBeVisible();

	// admin-console holds PROPOSER_ROLE, so it schedules from here
	await dialog.getByRole("button", { name: "Schedule", exact: true }).click();
	await expect(dialog).toHaveCount(0, { timeout: 30_000 });
	const operations = page.getByTestId("timelock-operations");
	await expect(operations).toContainText(getAddress(NEW_HOLDER), {
		timeout: 30_000,
	});

	await waitOutTheDelay(page);
	const row = operations
		.locator("[data-testid^=operation-]")
		.filter({ hasText: getAddress(NEW_HOLDER) });
	await expect(row).toContainText("ready", { timeout: 30_000 });
	await row.getByRole("button", { name: "Execute" }).click();
	await page
		.getByRole("alertdialog", { name: "Execute the timelock operation" })
		.getByRole("button", { name: "Execute" })
		.click();

	// both calls landed in the one transaction
	await expect
		.poll(() => holds("PAUSER_ROLE", NEW_HOLDER), { timeout: 30_000 })
		.toBe(true);
	expect(await holds("PAUSER_ROLE", OLD_HOLDER)).toBe(false);
});

test("a scheduled change is cancelled by the canceller and never executes", async ({
	page,
}) => {
	await openWithTimelock(page);
	const before = await reader.readContract({
		address: paymaster,
		abi: ROLE_ABI,
		functionName: "defaultFeeWei",
	});

	await page
		.getByLabel("Change", { exact: true })
		.selectOption("setDefaultFee");
	await page.getByRole("textbox", { name: "Fee" }).fill("0.0009");
	await page.getByRole("button", { name: "Build proposal" }).click();
	const dialog = page.getByRole("dialog", { name: "Timelock proposal" });
	await expect(dialog.getByTestId("proposal-result")).toBeVisible();
	const idText = await dialog
		.getByRole("button", { name: /^Copy Operation id/ })
		.textContent();
	const id = idText?.match(/0x[0-9a-f]{64}/)?.[0];
	if (!id) throw new Error(`no operation id in "${idText}"`);
	await dialog.getByRole("button", { name: "Schedule", exact: true }).click();
	await expect(dialog).toHaveCount(0, { timeout: 30_000 });

	const row = page.getByTestId(`operation-${id}`);
	await expect(row).toContainText("waiting", { timeout: 30_000 });
	await row.getByRole("button", { name: "Cancel", exact: true }).click();
	await page
		.getByRole("alertdialog", { name: "Cancel the timelock operation" })
		.getByRole("button", { name: "Cancel operation" })
		.click();

	await page.getByLabel("Show operations").selectOption("cancelled");
	await expect(page.getByTestId(`operation-${id}`)).toContainText("cancelled", {
		timeout: 30_000,
	});
	await waitOutTheDelay(page);
	expect(
		await reader.readContract({
			address: paymaster,
			abi: ROLE_ABI,
			functionName: "defaultFeeWei",
		}),
	).toBe(before);
});

test("Health checks the timelock: who else holds its roles, a delay below the published one, and the release", async ({
	page,
}) => {
	// The timelock waits 2s for everything; the deployment publishes an hour for upgrades.
	await openWithTimelock(page, { minDelay: 2, upgradeToAndCall: 3600 });
	await tab(page, /Health/).click();

	// admin-console keeps every role beside this file's timelock, which holds ROLE_ADMIN only.
	const roles = page.getByTestId("check-timelocked-roles");
	await expect(roles).toContainText("failing");
	await expect(roles).toContainText(
		`${getAddress(OPERATOR)} also holds ROLE_ADMIN, UPGRADER_ROLE, FEE_ADMIN_ROLE, WITHDRAW_ADDRESS_ADMIN_ROLE`,
	);
	await expect(roles).toContainText(
		`the timelock ${getAddress(timelock)} does not hold UPGRADER_ROLE, FEE_ADMIN_ROLE, WITHDRAW_ADDRESS_ADMIN_ROLE`,
	);
	await expect(page.getByTestId("check-timelock-delays")).toContainText(
		"upgradeToAndCall waits 2s, below the published 1h",
	);
	await expect(page.getByTestId("check-implementation")).toContainText(
		"release v2",
	);
	// The timelock is configured, so nothing says there is none, or asks to verify a holder.
	await expect(page.getByTestId("check-timelock")).toHaveCount(0);
	await expect(page.getByText(/verify this is the timelock/)).toHaveCount(0);
	for (const id of ["timelocked-roles", "timelock-delays", "implementation"])
		await expect(
			page.getByTestId("health-keys").getByTestId(`check-${id}`),
		).toBeVisible();
});
