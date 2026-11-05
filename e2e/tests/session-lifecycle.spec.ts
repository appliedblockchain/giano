import { expect, type Page, test } from "@playwright/test";
import {
	addVirtualAuthenticator,
	apiCall,
	connectWallet,
	openManagePopup,
	platformSignIn,
	seedCredentials,
	TENANTS,
} from "./helpers";

/**
 * The wallet session lifecycle as the user meets it (G5, openspec change session-lifecycle):
 * sign out everywhere, and a session a tenant admin revoked. Idle expiry and the per-user cap
 * are covered in wallet-api's tests, where time can be moved.
 */

const tenant = TENANTS.stock;

/** An authenticated management action: renaming the current passkey. */
async function rename(popup: Page, name: string) {
	await popup.getByTestId("manage-rename").click();
	await popup.getByTestId("manage-rename-input").fill(name);
	await popup.getByTestId("manage-rename-save").click();
}

test("sign out everywhere ends the session on the other device too", async ({
	page,
	browser,
}) => {
	const { credentials, address } = await connectWallet(page, tenant);
	const popup = await openManagePopup(page, credentials);
	await expect(popup.getByTestId("settings-address")).toHaveText(address);

	// A second device: its own browser, the same passkey, signed in on the wallet origin.
	const other = await browser.newContext();
	try {
		const device = await other.newPage();
		await device.goto(tenant.walletUrl);
		const { cdp, authenticatorId } = await addVirtualAuthenticator(device);
		await seedCredentials(cdp, authenticatorId, credentials);
		await device.getByTestId("manage-sign-in-existing").click();
		await expect(device.getByTestId("settings-address")).toHaveText(address);

		await popup.getByTestId("manage-logout-all").click();
		await expect(popup.getByTestId("manage-notice")).toHaveText(
			"You're signed out on every device.",
		);

		await rename(device, "after sign-out everywhere");
		await expect(device.getByTestId("manage-notice")).toHaveText(
			"Your session ended. Sign in again.",
		);
		await expect(device.getByTestId("manage-sign-in")).toBeVisible();
	} finally {
		await other.close();
	}
});

test("a tenant admin revokes the user's sessions, and the wallet asks for a sign-in", async ({
	page,
}) => {
	const { credentials, address } = await connectWallet(page, tenant);
	const popup = await openManagePopup(page, credentials);
	await expect(popup.getByTestId("settings-address")).toHaveText(address);
	const externalUserId = await popup.evaluate(() =>
		localStorage.getItem("giano:external-user-id"),
	);
	expect(externalUserId).toBeTruthy();

	const revoked = await apiCall("POST", "/v1/admin/sessions/revoke", {
		body: { externalUserId },
		headers: { authorization: `Bearer ${tenant.adminKey}` },
	});
	expect(revoked.status).toBe(200);
	expect(revoked.json().revoked).toBeGreaterThanOrEqual(1);

	await rename(popup, "after revocation");
	await expect(popup.getByTestId("manage-notice")).toHaveText(
		"Your session ended. Sign in again.",
	);
	await expect(popup.getByTestId("manage-sign-in")).toBeVisible();

	// The revocation is in the tenant's history, attributed to the admin key.
	const token = await platformSignIn();
	const history = await apiCall(
		"GET",
		`/v1/platform/tenants/${tenant.slug}/history`,
		{ headers: { authorization: `Bearer ${token}` } },
	);
	expect(history.status).toBe(200);
	const entry = history
		.json()
		.entries.find(
			(row: { action: string; detail: { value?: string } | null }) =>
				row.action === "user-sessions-revoke" &&
				row.detail?.value === externalUserId,
		);
	expect(entry).toMatchObject({
		actor: expect.stringMatching(/^tenant-admin-key:/),
		detail: { selector: "externalUserId", revoked: revoked.json().revoked },
	});
});
