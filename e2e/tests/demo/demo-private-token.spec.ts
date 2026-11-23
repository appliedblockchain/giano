import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Locator, test } from "@playwright/test";
import { type Address, encodeFunctionData, erc20Abi, toHex } from "viem";
import { CHAINS, loopbackOf, ORIGINS } from "../../origins.mjs";
import {
	connectDemo,
	connectDemoOnChain,
	getPosition,
	getSpend,
	openActionPopup,
	TENANTS,
} from "../helpers";

/**
 * The demo's private token section on chain 31339, "Devnet SD (Silent Data)": an anvil node behind
 * Silent Data's gateway (openspec/changes/local-silent-data-chain, design D7). Opt-in, like every
 * spec under tests/demo: `pnpm test:demo`.
 *
 * 1. The gateway check, with no browser. It proves that the gateway, not the node, answers rpc-sd.
 *    The node answers every read, so without this check the flows below would prove nothing private.
 * 2. The flow, once for `stock` (wallet-web) and once for `byo` (the BYO wallet fixture): the
 *    undeployed-wallet message, mint, the read-delegate approval, the signed read, transfer and the
 *    outsider view. Then the settlement and the tenant's debit on 31339.
 *
 * Every run uses a new passkey, so a new wallet with no balance: the test does not need a fresh chain.
 */

const ADDRESSES = JSON.parse(
	fs.readFileSync(
		path.resolve(
			path.dirname(fileURLToPath(import.meta.url)),
			"../../devnet/addresses.json",
		),
		"utf8",
	),
) as { privateTestErc20: Address };
const PRIVATE_ERC20 = ADDRESSES.privateTestErc20;
const SYMBOL = "GTPT";

const GATEWAY = ORIGINS.rpcSd;
const NODE = loopbackOf("rpc-sd-node");

/** `UCEFUnauthorizedBalanceAccess(address,address)`: the private token refuses a balance read. */
const BALANCE_REFUSAL = "0xdb11736b";
/** The gateway's error code for a method it does not allow. */
const METHOD_NOT_ALLOWED = -87926;

/** The transfer's recipient. Any address works: the outsider view reads its balance and is refused. */
const RECIPIENT = "0x000000000000000000000000000000000000beef";

// ── the gateway check ─────────────────────────────────────────────────────────

type RpcReply = {
	result?: unknown;
	error?: { code: number; message: string; data?: unknown };
};

async function rpc(
	url: string,
	method: string,
	params: unknown[],
): Promise<RpcReply> {
	const response = await fetch(url, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
	});
	// The gateway answers a method it does not allow with HTTP 403 and a JSON-RPC error, so the
	// status alone says nothing. Every answer must be JSON-RPC.
	const text = await response.text();
	try {
		return JSON.parse(text) as RpcReply;
	} catch {
		throw new Error(
			`${method} at ${url}: HTTP ${response.status}, not JSON-RPC: ${text}`,
		);
	}
}

/** The failure message when rpc-sd answers what only the node should answer. */
const notTheGateway = (what: string) =>
	`${GATEWAY} ${what}. Chain 31339's RPC is not behind Silent Data's gateway: check that the rpc-sd route and the stack's sd-gateway service forward to the gateway (port 8548), not to the node (port 8547).`;

test("Devnet SD: the gateway refuses what the node answers", async () => {
	for (const url of [GATEWAY, NODE])
		expect(
			(await rpc(url, "eth_chainId", [])).result,
			`${url} is not chain ${CHAINS.sd.chainId}`,
		).toBe(toHex(CHAINS.sd.chainId));

	// An unsigned balance read, with `from` set to the holder. The node runs it as the holder, so the
	// private token answers. The gateway replaces `from` on an unsigned call, so the token refuses it.
	const holder = RECIPIENT;
	const read = [
		{
			from: holder,
			to: PRIVATE_ERC20,
			data: encodeFunctionData({
				abi: erc20Abi,
				functionName: "balanceOf",
				args: [holder],
			}),
		},
		"latest",
	];
	// A call to an address with no code returns "0x" and no error, so check the result is a balance.
	const atNode = await rpc(NODE, "eth_call", read);
	expect(atNode.error, "the node refused the read").toBeUndefined();
	expect(
		atNode.result,
		`the node returned no balance: is the private test ERC-20 missing at ${PRIVATE_ERC20} on chain 31339?`,
	).toMatch(/^0x[0-9a-fA-F]{64}$/);
	const atGateway = await rpc(GATEWAY, "eth_call", read);
	expect(
		atGateway.error,
		notTheGateway(
			"answered an unsigned balanceOf with `from` set to the holder",
		),
	).toBeDefined();
	expect(String(atGateway.error?.data)).toMatch(
		new RegExp(`^${BALANCE_REFUSAL}`),
	);

	// eth_getStorageAt would read the balance from storage, so the gateway refuses the method.
	const storage = [PRIVATE_ERC20, "0x0", "latest"];
	expect((await rpc(NODE, "eth_getStorageAt", storage)).error).toBeUndefined();
	const storageAtGateway = await rpc(GATEWAY, "eth_getStorageAt", storage);
	expect(
		storageAtGateway.error?.code,
		notTheGateway("answered eth_getStorageAt"),
	).toBe(METHOD_NOT_ALLOWED);
});

// ── the flow ──────────────────────────────────────────────────────────────────

const USER_OPERATION = /user operation\s*(0x[0-9a-fA-F]{64})/;

/**
 * The full user operation hash, from the row's details. The section lists only its three latest
 * outcomes, so read the hash as soon as the row is confirmed.
 */
async function userOpHashOf(row: Locator): Promise<string> {
	// Click the row's trigger, not the row: the centre of an open row is in its details.
	const trigger = row.locator(":scope > button");
	await trigger.click();
	await expect(row).toContainText(USER_OPERATION);
	const hash = ((await row.textContent()) ?? "").match(USER_OPERATION)?.[1];
	await trigger.click();
	if (!hash) throw new Error("no user operation hash in the row");
	return hash;
}

const FLOWS = [
	{ tenant: TENANTS.stock, demo: ORIGINS.demo },
	{ tenant: TENANTS.byo, demo: ORIGINS.demoByo },
];

for (const { tenant, demo } of FLOWS) {
	test(`${tenant.slug}: mint, signed read, transfer and the outsider view on Devnet SD`, async ({
		page,
	}) => {
		test.setTimeout(300_000);
		// Connect on Devnet A through the header, then on Devnet SD with the same passkey.
		const credentials = await connectDemo(page, tenant, demo);
		await connectDemoOnChain(page, tenant, CHAINS.sd, credentials);
		await page.getByTestId("tab-tokens").click();
		const section = page.locator("#private-token");
		const balance = section
			.getByText("Your balance", { exact: true })
			.locator("..");
		const confirmed = (label: string) =>
			section
				.locator("[data-testid=outcome-row][data-status=confirmed]")
				.filter({ hasText: label });

		// A new wallet is not deployed, and the RPC checks a signed read against the wallet's code.
		await expect(section.getByText("Deploy the wallet first.")).toBeVisible({
			timeout: 20_000,
		});
		await expect(section.getByTestId("private-read")).toBeDisabled();
		const before = await getPosition(tenant, CHAINS.sd.chainId);

		// Mint 100: sponsored, confirmed from its receipt. The user operation deploys the wallet.
		await section.getByLabel(`Amount (${SYMBOL})`).fill("100");
		const mintPopup = await openActionPopup(
			page,
			"[data-testid=private-mint]",
			credentials,
		);
		await expect(mintPopup.getByTestId("consent-chain")).toContainText(
			CHAINS.sd.name,
		);
		await mintPopup
			.getByRole("button", { name: tenant.ui.approveTx, exact: true })
			.click();
		const mint = confirmed(`Mint 100 ${SYMBOL}`);
		await expect(mint).toBeVisible({ timeout: 90_000 });
		await expect(mint).toContainText("gas paid by the app");
		const hashes = [await userOpHashOf(mint)];
		await expect(section.getByText("Deploy the wallet first.")).toHaveCount(0);

		// The signed read asks the wallet once to approve the read delegate (personal_sign).
		const readPopup = await openActionPopup(
			page,
			"[data-testid=private-read]",
			credentials,
		);
		await readPopup
			.getByRole("button", { name: tenant.ui.sign, exact: true })
			.click();
		await expect(balance).toContainText(`100 ${SYMBOL}`, { timeout: 30_000 });

		// Transfer 40: with the delegate approved, the section reads the balance again, with no popup.
		await section.getByLabel(`Amount (${SYMBOL})`).fill("40");
		await section.getByLabel("Recipient").fill(RECIPIENT);
		const transferPopup = await openActionPopup(
			page,
			"[data-testid=private-transfer]",
			credentials,
		);
		await transferPopup
			.getByRole("button", { name: tenant.ui.approveTx, exact: true })
			.click();
		const transfer = confirmed(`Transfer 40 ${SYMBOL}`);
		await expect(transfer).toBeVisible({ timeout: 90_000 });
		await expect(transfer).toContainText("gas paid by the app");
		hashes.push(await userOpHashOf(transfer));
		await expect(balance).toContainText(`60 ${SYMBOL}`, { timeout: 30_000 });

		// The outsider view: the unsigned read and the read of another account are refused, and the
		// transfer's bundle transaction comes back with placeholders.
		await section.getByTestId("private-outsider").click();
		const outsider = section.getByTestId("private-outsider-view");
		const outcomeOf = (label: string | RegExp) =>
			outsider.getByText(label).locator("..");
		await expect(
			outcomeOf("Your balance, read without a signature"),
		).toContainText("refused", { timeout: 30_000 });
		await expect(
			outcomeOf(/^Balance of .+, signed for your wallet$/),
		).toContainText("refused");
		await expect(
			outcomeOf("Your latest transfer's bundle transaction, unsigned"),
		).toContainText("hidden");

		// Both user operations settle on 31339. The tenant's balance then falls by exactly the
		// settlements in the blocks between the two balance reads. Another user operation of this
		// tenant can land in that range, such as one that a timed-out first attempt left with the
		// bundler. It counts on both sides, so the check still holds.
		await expect(async () => {
			const after = await getPosition(tenant, CHAINS.sd.chainId);
			const { settlements } = await getSpend(tenant, CHAINS.sd.chainId);
			for (const hash of hashes) {
				const row = settlements.find(
					(settlement) =>
						settlement.useropHash.toLowerCase() === hash.toLowerCase(),
				);
				expect(
					row,
					`wallet-api has not settled ${hash} on 31339`,
				).toBeDefined();
				expect(row?.success, `the settlement of ${hash}`).toBe(true);
				expect(BigInt(row?.totalWei ?? 0)).toBeGreaterThan(0n);
			}
			const between = settlements.filter(
				(settlement) =>
					BigInt(settlement.blockNumber) > BigInt(before.blockNumber) &&
					BigInt(settlement.blockNumber) <= BigInt(after.blockNumber),
			);
			expect(
				BigInt(before.balanceWei) - BigInt(after.balanceWei),
				`the debit between blocks ${before.blockNumber} and ${after.blockNumber}, against its ${between.length} settlements`,
			).toBe(
				between.reduce(
					(sum, settlement) => sum + BigInt(settlement.totalWei),
					0n,
				),
			);
		}).toPass({ timeout: 30_000 });
	});
}
