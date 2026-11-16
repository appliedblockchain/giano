/**
 * The rehearsal's platform smoke test (playwright.rehearsal.config.ts): on a fork of a public testnet,
 * against contracts deployed through the real adoption path, a new user creates a passkey wallet, which
 * deploys the account in a sponsored operation, then sends a sponsored transaction, and the paymaster
 * books both against the tenant.
 *
 * `#send` is a zero-value self-call, which the sponsorship rules treat as wallet management, governed
 * by platform policy rather than the tenant's allowlist. A public testnet carries no demo ERC-20
 * (R-29), so the rehearsal allow-lists a stand-in contract (SPONSOR_ALLOWLIST): with an empty
 * allowlist the wallet-api sponsors nothing at all.
 */
import { expect, test } from "@playwright/test";
import { createPublicClient, http, parseAbi } from "viem";
import {
	connectWallet,
	expectOutContains,
	openActionPopup,
	TENANTS,
} from "../tests/helpers";

const FORK_RPC = process.env.REHEARSAL_FORK_RPC ?? "http://127.0.0.1:18545";
const PAYMASTER = process.env.SPONSORSHIP_PAYMASTER_ADDRESS as `0x${string}`;
const TENANT_ID = (process.env.TENANT_ID ?? "").replaceAll("-", "");
const tenant = TENANTS.stock;

const paymaster = parseAbi([
	"function getTenant(bytes16) view returns ((bool registered, bool enabled, bool hasFeeOverride, address withdrawAddress, uint128 balance, uint128 deficit, uint128 feeWeiOverride))",
]);
const client = createPublicClient({ transport: http(FORK_RPC) });
const tenantBalance = async () =>
	(
		await client.readContract({
			address: PAYMASTER,
			abi: paymaster,
			functionName: "getTenant",
			args: [`0x${TENANT_ID}`],
		})
	).balance;

test("a new passkey wallet is deployed and sends a sponsored transaction, both paid from the tenant's balance", async ({
	page,
}) => {
	expect(PAYMASTER, "SPONSORSHIP_PAYMASTER_ADDRESS").toMatch(
		/^0x[0-9a-fA-F]{40}$/,
	);
	expect(TENANT_ID, "TENANT_ID").toHaveLength(32);
	const funded = await tenantBalance();
	expect(funded).toBeGreaterThan(0n);

	// Connecting registers the passkey and deploys the account through the factory, in a sponsored
	// operation of its own (as wallet-management.spec.ts expects on the devnet).
	const { credentials, address } = await connectWallet(page, tenant);
	const code = () => client.getCode({ address: address as `0x${string}` });
	await expect.poll(code, { timeout: 30_000 }).toMatch(/^0x.+/);
	await expect.poll(tenantBalance, { timeout: 30_000 }).toBeLessThan(funded);
	const afterDeploy = await tenantBalance();

	const popup = await openActionPopup(page, "#send", credentials);
	await expect(popup.getByText(tenant.ui.txHeading)).toBeVisible();
	await popup.getByRole("button", { name: tenant.ui.approveTx }).click();
	await expectOutContains(page, "userOpHash: 0x");
	await expectOutContains(page, "receipt:success: true");

	await expect
		.poll(tenantBalance, { timeout: 30_000 })
		.toBeLessThan(afterDeploy);
	console.log(
		`account ${address}; tenant balance ${funded} -> ${afterDeploy} (deploy) -> ${await tenantBalance()} (send)`,
	);
});
