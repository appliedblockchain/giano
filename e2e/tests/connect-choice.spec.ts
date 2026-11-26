import { expect, type Page, test } from "@playwright/test";
import {
	addVirtualAuthenticator,
	connectWallet,
	openWalletPopup,
	seedCredentials,
	TENANTS,
	trackResidentCredentials,
} from "./helpers";

/**
 * How a connect signs in when there is no session. The external user id a browser stores names
 * whom it last knew, not which passkeys it holds, so the connect screen offers both choices:
 * sign in with a passkey the device holds (any user, any wallet), or create a new wallet.
 */

const tenant = TENANTS.stock;

/** Every address the dApp has reported from a connect, in order. */
async function connectedAddresses(dapp: Page): Promise<string[]> {
	const out = (await dapp.getByTestId("out").textContent()) ?? "";
	return [...out.matchAll(/accounts: \["(0x[0-9a-fA-F]{40})"/g)].map(
		(match) => match[1],
	);
}

test("a returning user on a fresh browser signs in with the passkey they hold, through 'Use a passkey I already have'", async ({
	page,
	browser,
}) => {
	const { credentials, address } = await connectWallet(page, tenant);

	// The same passkey, synced to a browser that has never seen this wallet origin.
	const fresh = await browser.newContext();
	try {
		const dapp = await fresh.newPage();
		await dapp.goto(tenant.dappUrl);
		const connect = await openWalletPopup(dapp, "#connect");
		const { cdp, authenticatorId } = await addVirtualAuthenticator(connect);
		await seedCredentials(cdp, authenticatorId, credentials);
		const created = trackResidentCredentials(cdp);

		await connect.getByTestId("connect-existing-passkey").click();

		await expect
			.poll(() => connectedAddresses(dapp), { timeout: 90_000 })
			.toEqual([address]);
		expect(created).toHaveLength(0);
	} finally {
		await fresh.close();
	}
});

test("a signed-out device that holds a passkey can still create a new wallet, through 'Create a new wallet'", async ({
	page,
}) => {
	const { address } = await connectWallet(page, tenant);

	// Sign out on the wallet origin: the device keeps its passkey, but has no session.
	const wallet = await page.context().newPage();
	await wallet.goto(tenant.walletUrl);
	const storedUser = () =>
		wallet.evaluate(() => localStorage.getItem("giano:external-user-id"));
	const userBefore = await storedUser();
	await wallet
		.getByRole("button", { name: "Log out (revoke session)" })
		.click();
	await expect(wallet.getByTestId("manage-sign-in")).toBeVisible();

	const connect = await openWalletPopup(page, "#connect");
	const { cdp } = await addVirtualAuthenticator(connect);
	const created = trackResidentCredentials(cdp);
	// The device is known to hold a passkey: signing in is the default, creating the alternative.
	await expect(connect.getByTestId("connect-explanation")).toContainText(
		"passkey this device holds",
	);
	await connect.getByTestId("connect-new-wallet").click();

	await expect
		.poll(async () => (await connectedAddresses(page)).length, {
			timeout: 90_000,
		})
		.toBe(2);
	const [first, second] = await connectedAddresses(page);
	expect(first).toBe(address);
	expect(second.toLowerCase()).not.toBe(address.toLowerCase());
	expect(created).toHaveLength(1);
	// The new wallet belongs to a new user: the old one already had a wallet.
	expect(await storedUser()).not.toBe(userBefore);
});
