import {
	type Browser,
	type BrowserContext,
	expect,
	type Page,
	test,
} from "@playwright/test";
import {
	addVirtualAuthenticator,
	connectWallet,
	expectOutContains,
	openActionPopup,
	openManagePopup,
	openWalletPopup,
	readOnChainOwners,
	seedCredentials,
	TENANTS,
	trackResidentCredentials,
	type VirtualCredential,
} from "./helpers";

/**
 * One wallet, two devices (WM-18…WM-23, WM-30…WM-35, WM-67). Each device is its own browser
 * context, so each has its own wallet-origin storage, its own session and its own virtual
 * authenticator. A passkey created on one device is never seeded into the other: device B can
 * only use the passkey it created, as a real second device would.
 *
 * Device A creates the wallet. Device B joins it through the claim code and the fingerprint
 * comparison. Every test asserts the ON-CHAIN owner set, and that device B acts for device A's
 * wallet: the address does not change when an owner is added (WM-12, WM-15).
 */

const tenant = TENANTS.stock;

/**
 * Known bugs these tests expose. A test marked with one of them is expected to fail until the
 * bug is fixed; remove the mark in the change that fixes it.
 */
const KNOWN_BUG = {
	/** ClaimFlow maps `pending-declined` to the "connection problem" copy (WM-23). */
	declinedCopy: "a declined claim code reads as a network failure",
	/**
	 * A device that never signed in on the wallet origin holds its own random external user id, so
	 * its first dApp connect finds no credentials and registers a NEW passkey and wallet, instead of
	 * signing in with the passkey it holds. Hits a joined device B, and any returning user on a fresh
	 * browser or after clearing site data.
	 */
	connectCreatesWallet:
		"connect on a fresh browser registers a new wallet instead of signing in",
};

/** Anvil account #1, a checksummed address used as an owner (no transaction is sent from it). */
const EOA = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

const FINGERPRINT = /^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/;

type DeviceA = {
	page: Page;
	/** The management popup, still open after the pairing. */
	popup: Page;
	credentials: VirtualCredential[];
	address: string;
};

type DeviceB = {
	context: BrowserContext;
	/** The wallet origin, opened directly. Its virtual authenticator holds device B's passkey. */
	wallet: Page;
	credentials: VirtualCredential[];
	fingerprint: string;
};

/** Device A: a new wallet on the dApp, with its management popup open. */
async function startDeviceA(page: Page): Promise<DeviceA> {
	const { credentials, address } = await connectWallet(page, tenant);
	const popup = await openManagePopup(page, credentials);
	await expect(popup.getByTestId("settings-address")).toHaveText(address);
	return { page, popup, credentials, address };
}

/** Device B: a separate browser on the wallet origin, signed out, with an empty authenticator. */
async function startDeviceB(browser: Browser) {
	const context = await browser.newContext();
	const wallet = await context.newPage();
	await wallet.goto(tenant.walletUrl);
	// Device B keeps its passkey in a synced password manager; device A's stays on the device. The
	// management list must tell them apart (PS-1).
	const { cdp } = await addVirtualAuthenticator(wallet, { synced: true });
	const credentials = trackResidentCredentials(cdp);
	// Device B signs here and then in dApp popups, each with its own virtual authenticator. A real
	// device has one authenticator, so carry the signature counter forward from this page too, or
	// wallet-api refuses the popup's first signature as a counter regression.
	cdp.on(
		"WebAuthn.credentialAsserted" as never,
		((event: { credential: VirtualCredential }) => {
			const index = credentials.findIndex(
				(credential) =>
					credential.credentialId === event.credential.credentialId,
			);
			if (index !== -1) credentials[index] = event.credential;
		}) as never,
	);
	await expect(wallet.getByTestId("manage-claim-entry")).toBeVisible();
	return { context, wallet, credentials };
}

/**
 * Device A opens a pending addition; device B enters the claim code and creates its passkey.
 * Returns the fingerprint each device shows. Nothing has been signed yet.
 */
async function offerDeviceB(a: DeviceA, browser: Browser) {
	await a.popup.getByTestId("manage-add-device").click();
	const code = (
		await a.popup.getByTestId("manage-claim-code").textContent({
			timeout: 30_000,
		})
	)?.trim();
	expect(code).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}$/);

	const b = await startDeviceB(browser);
	await b.wallet.getByTestId("manage-claim-entry").click();
	await b.wallet.getByTestId("manage-claim-input").fill(code as string);
	await b.wallet.getByTestId("manage-claim-continue").click();
	const onB = b.wallet.getByTestId("manage-claim-fingerprint");
	await expect(onB).toHaveText(FINGERPRINT, { timeout: 30_000 });
	expect(b.credentials).toHaveLength(1);

	const onA = a.popup.getByTestId("manage-consent-fingerprint");
	await expect(onA).toHaveText(FINGERPRINT, { timeout: 30_000 });
	return {
		b,
		code: code as string,
		fingerprintOnA: (await onA.textContent()) as string,
		fingerprintOnB: (await onB.textContent()) as string,
	};
}

/** The whole pairing: offer, compare, approve on device A, and wait for the chain. */
async function pairDeviceB(a: DeviceA, browser: Browser): Promise<DeviceB> {
	const { b, fingerprintOnA, fingerprintOnB } = await offerDeviceB(a, browser);
	// WM-20, WM-21: the user approves only when both screens show the same fingerprint.
	expect(fingerprintOnA).toBe(fingerprintOnB);
	await a.popup.getByTestId("manage-fingerprint-approve").click();
	await expect(a.popup.getByTestId("manage-flow-done")).toBeVisible({
		timeout: 120_000,
	});
	await expect(
		a.popup.getByText("Passkey added", { exact: true }),
	).toBeVisible();
	return {
		context: b.context,
		wallet: b.wallet,
		credentials: b.credentials,
		fingerprint: fingerprintOnB,
	};
}

/** Device B, on the wallet origin: back to the signed-out view, then a discoverable sign-in. */
async function signInDeviceB(b: DeviceB) {
	await b.wallet.getByTestId("manage-flow-done").click();
	await b.wallet.getByTestId("manage-sign-in-existing").click();
}

/** A CDP credential id (base64) as wallet-api writes it (base64url, no padding). */
function apiCredentialId(credential: VirtualCredential): string {
	return Buffer.from(credential.credentialId as string, "base64").toString(
		"base64url",
	);
}

/** What wallet-api says the session held by this wallet-origin page is: its passkey and its wallet. */
async function sessionOf(walletPage: Page) {
	const token = await walletPage.evaluate(() =>
		localStorage.getItem("giano:session-token"),
	);
	expect(token, "the wallet origin holds a session").not.toBeNull();
	const response = await walletPage
		.context()
		.request.get(`${tenant.walletUrl}/api/v1/me`, {
			headers: {
				authorization: `Bearer ${token}`,
				origin: tenant.walletUrl,
			},
		});
	expect(response.status()).toBe(200);
	return (await response.json()) as {
		walletAddress: string;
		credentialId: string;
	};
}

/** The owner row whose fingerprint is the given one. */
function ownerRow(page: Page, fingerprint: string) {
	return page.locator("[data-testid=manage-owner-row]", {
		has: page.getByTestId("manage-owner-fingerprint").getByText(fingerprint),
	});
}

test.describe("one wallet, two devices", () => {
	let deviceB: BrowserContext | undefined;
	test.afterEach(async () => {
		await deviceB?.close();
		deviceB = undefined;
	});

	test("add a passkey from a second device: matching fingerprints, two owners on-chain, address unchanged (WM-18, WM-20, WM-21)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		expect((await readOnChainOwners(a.address)).owners).toHaveLength(1);

		const b = await pairDeviceB(a, browser);
		deviceB = b.context;

		const after = await readOnChainOwners(a.address);
		expect(after.owners).toHaveLength(2);
		expect(after.owners.every((owner) => owner.kind === "passkey")).toBe(true);

		// Device A's list, re-read from the chain: device B's key is an owner, and the registry
		// bound it to this wallet (it has the name given at consent, not "NOT an owner").
		await a.popup.getByTestId("manage-flow-done").click();
		await expect(a.popup.getByTestId("manage-owner-row")).toHaveCount(2, {
			timeout: 30_000,
		});
		const row = ownerRow(a.popup, b.fingerprint);
		await expect(row).toHaveCount(1);
		await expect(row.getByTestId("manage-owner-name")).toContainText(
			"Another device",
		);
		await expect(a.popup.getByTestId("manage-stray-credential")).toHaveCount(0);
	});

	test("the second device signs in to the same wallet, and its own passkey is marked current (WM-33, WM-10)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;

		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);
		await expect(b.wallet.getByTestId("manage-owner-row")).toHaveCount(2);
		await expect(
			ownerRow(b.wallet, b.fingerprint).getByTestId("manage-owner-current"),
		).toBeVisible();
	});

	test("the second device connects from the dApp and sends a sponsored transaction from the same wallet (WM-33, WM-34)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;
		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);

		// Device B's dApp: the same browser as its wallet-origin sign-in, and only its own passkey.
		const dapp = await b.context.newPage();
		await dapp.goto(tenant.dappUrl);
		const connect = await openWalletPopup(dapp, "#connect");
		const { cdp, authenticatorId } = await addVirtualAuthenticator(connect);
		await seedCredentials(cdp, authenticatorId, b.credentials);
		await connect.getByRole("button", { name: tenant.ui.connect }).click();
		// Wait for the connect to end either way, so a failure reports its reason at once.
		const out = dapp.getByTestId("out");
		await expect(out).toContainText(/accounts: \[|connect:error/, {
			timeout: 90_000,
		});
		await expect(out).toContainText(`accounts: ["${a.address}"`);
		// The connect signed in device B's own passkey: the session it stored (shared with the wallet
		// page, same origin and browser) is bound to it. The popup itself has closed.
		expect((await sessionOf(b.wallet)).credentialId).toBe(
			apiCredentialId(b.credentials[0]),
		);

		// The operation is signed by device B's passkey: its signature counter moves.
		const signCount = () => b.credentials[0].signCount as number;
		const before = signCount();
		const send = await openActionPopup(dapp, "#send", b.credentials);
		await expect(send.getByText(tenant.ui.txHeading)).toBeVisible();
		await send.getByRole("button", { name: tenant.ui.approveTx }).click();
		await expectOutContains(dapp, "receipt:success: true");
		await expectOutContains(dapp, `"account":"${a.address}"`);
		expect(signCount()).toBeGreaterThan(before);
	});

	test("the first device still signs after the second joins (WM-33)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;
		// Device B signs in, so both passkeys have been used against wallet-api.
		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);

		await a.popup.getByTestId("manage-flow-done").click();
		await Promise.all([
			a.popup.waitForEvent("close"),
			a.popup.getByTestId("manage-close").click(),
		]);
		const send = await openActionPopup(a.page, "#send", a.credentials);
		await send.getByRole("button", { name: tenant.ui.approveTx }).click();
		await expectOutContains(a.page, "receipt:success: true");
		await expectOutContains(a.page, `"account":"${a.address}"`);
	});

	test("a declined fingerprint adds nothing, and the claim code cannot be used again (WM-21, WM-22, WM-23)", async ({
		page,
		browser,
	}) => {
		test.fail(true, KNOWN_BUG.declinedCopy);
		const a = await startDeviceA(page);
		const { b, code } = await offerDeviceB(a, browser);
		deviceB = b.context;

		await a.popup.getByTestId("manage-fingerprint-decline").click();
		await expect(a.popup.getByTestId("manage-declined-note")).toBeVisible();
		expect((await readOnChainOwners(a.address)).owners).toHaveLength(1);

		// The new device's passkey was never added, so it cannot sign in to the wallet.
		await b.wallet.getByTestId("manage-flow-done").click();
		await b.wallet.getByTestId("manage-claim-entry").click();
		await b.wallet.getByTestId("manage-claim-input").fill(code);
		await b.wallet.getByTestId("manage-claim-continue").click();
		const error = b.wallet.getByTestId("manage-claim-error");
		await expect(error).toBeVisible({ timeout: 30_000 });
		await expect(error).toHaveAttribute("data-code", /^pending-/);
		// WM-23: the refusal must not read as a network failure.
		await expect(error).not.toContainText("connection problem");
	});

	test("the first device removes the second: gone on-chain, and the second device can no longer sign in (WM-27, WM-31)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;

		await a.popup.getByTestId("manage-flow-done").click();
		const row = ownerRow(a.popup, b.fingerprint);
		await expect(row).toHaveCount(1, { timeout: 30_000 });
		await row.getByTestId("manage-remove").click();
		await expect(
			a.popup.getByTestId("manage-remove-current-warning"),
		).toHaveCount(0);
		await a.popup.getByTestId("manage-remove-approve").click();
		await expect(a.popup.getByTestId("manage-flow-done")).toBeVisible({
			timeout: 120_000,
		});

		const after = await readOnChainOwners(a.address);
		expect(after.owners).toHaveLength(1);

		// WM-31: refused with a reason that says the passkey is no longer an owner.
		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("manage-error")).toContainText(
			"no longer an owner",
			{ timeout: 30_000 },
		);
		await expect(b.wallet.getByTestId("settings-address")).toHaveCount(0);
	});

	test("the second device removes its own passkey: gone on-chain, and it is signed out (WM-30)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;
		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);

		await ownerRow(b.wallet, b.fingerprint)
			.getByTestId("manage-remove")
			.click();
		await expect(
			b.wallet.getByTestId("manage-remove-current-warning"),
		).toBeVisible();
		await b.wallet.getByTestId("manage-remove-approve").click();
		// The flow ends with a done button whatever the outcome; wait for it, then read the outcome.
		await expect(b.wallet.getByTestId("manage-flow-done")).toBeVisible({
			timeout: 90_000,
		});
		await expect(
			b.wallet.getByTestId("manage-removed-signed-out"),
		).toBeVisible();

		const after = await readOnChainOwners(a.address);
		expect(after.owners).toHaveLength(1);

		await b.wallet.getByTestId("manage-flow-done").click();
		await expect(b.wallet.getByTestId("manage-sign-in")).toBeVisible();
	});

	test("after joining, device B's session is its own passkey on the same wallet, and both devices list both passkeys by name (WM-07, WM-10, WM-33)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		// Device A names its own passkey first, so device B must show a name it never set.
		const ownRowOnA = a.popup.locator("[data-testid=manage-owner-row]", {
			has: a.popup.getByTestId("manage-owner-current"),
		});
		const fingerprintA = (await ownRowOnA
			.getByTestId("manage-owner-fingerprint")
			.textContent()) as string;
		await a.popup.getByTestId("manage-rename").click();
		await a.popup.getByTestId("manage-rename-input").fill("Laptop");
		await a.popup.getByTestId("manage-rename-save").click();
		await expect(ownRowOnA.getByTestId("manage-owner-name")).toHaveText(
			"Laptop",
		);

		const b = await pairDeviceB(a, browser);
		deviceB = b.context;
		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);

		// Device B's session: wallet-api binds it to device B's passkey and to device A's wallet.
		const onB = await sessionOf(b.wallet);
		expect(onB.credentialId).toBe(apiCredentialId(b.credentials[0]));
		expect(onB.walletAddress.toLowerCase()).toBe(a.address.toLowerCase());
		// Device A's session is unchanged: still device A's passkey.
		const onA = await sessionOf(a.popup);
		expect(onA.credentialId).toBe(apiCredentialId(a.credentials[0]));
		expect(onA.walletAddress.toLowerCase()).toBe(a.address.toLowerCase());

		// Device B lists both passkeys: its own marked current, device A's under the name A gave it.
		await expect(b.wallet.getByTestId("manage-owner-row")).toHaveCount(2);
		await expect(
			ownerRow(b.wallet, b.fingerprint).getByTestId("manage-owner-current"),
		).toBeVisible();
		await expect(
			ownerRow(b.wallet, fingerprintA).getByTestId("manage-owner-current"),
		).toHaveCount(0);
		await expect(
			ownerRow(b.wallet, fingerprintA).getByTestId("manage-owner-name"),
		).toHaveText("Laptop");

		// PS-1: each device sees where each passkey is stored.
		await expect(
			ownerRow(b.wallet, b.fingerprint).getByTestId("manage-owner-storage"),
		).toHaveText("Synced");
		await expect(
			ownerRow(b.wallet, fingerprintA).getByTestId("manage-owner-storage"),
		).toHaveText("This device only");

		// Device A lists both too, with its own passkey still the current one.
		await a.popup.getByTestId("manage-flow-done").click();
		await expect(a.popup.getByTestId("manage-owner-row")).toHaveCount(2, {
			timeout: 30_000,
		});
		await expect(
			ownerRow(a.popup, fingerprintA).getByTestId("manage-owner-current"),
		).toBeVisible();
		await expect(
			ownerRow(a.popup, b.fingerprint).getByTestId("manage-owner-current"),
		).toHaveCount(0);
		await expect(
			ownerRow(a.popup, b.fingerprint).getByTestId("manage-owner-storage"),
		).toHaveText("Synced");
	});

	test("device B logs out and signs in again: the same wallet, with its own passkey (WM-33)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;
		await signInDeviceB(b);
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);

		await b.wallet
			.getByRole("button", { name: "Log out (revoke session)" })
			.click();
		await b.wallet.getByTestId("manage-sign-in-existing").click();
		await expect(b.wallet.getByTestId("settings-address")).toHaveText(
			a.address,
			{ timeout: 30_000 },
		);
		const session = await sessionOf(b.wallet);
		expect(session.credentialId).toBe(apiCredentialId(b.credentials[0]));
		await expect(
			ownerRow(b.wallet, b.fingerprint).getByTestId("manage-owner-current"),
		).toBeVisible();
	});

	test("device B connects from the dApp straight after joining, without signing in on the wallet first (WM-33)", async ({
		page,
		browser,
	}) => {
		test.fail(true, KNOWN_BUG.connectCreatesWallet);
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;

		// The user goes from the claim screen to the application, as most will.
		const dapp = await b.context.newPage();
		await dapp.goto(tenant.dappUrl);
		const connect = await openWalletPopup(dapp, "#connect");
		const { cdp, authenticatorId } = await addVirtualAuthenticator(connect);
		await seedCredentials(cdp, authenticatorId, b.credentials);
		const created = trackResidentCredentials(cdp);
		await connect.getByRole("button", { name: tenant.ui.connect }).click();
		const out = dapp.getByTestId("out");
		await expect(out).toContainText(/accounts: \[|connect:error/, {
			timeout: 90_000,
		});
		// It signs in with the passkey it holds, to the wallet it joined: no new passkey, no new wallet.
		expect(created).toHaveLength(0);
		await expect(out).toContainText(`accounts: ["${a.address}"`);
		expect((await sessionOf(b.wallet)).credentialId).toBe(
			apiCredentialId(b.credentials[0]),
		);
	});

	test("an owner already removed by the other device is refused legibly, never with a bare revert (WM-29)", async ({
		page,
		browser,
	}) => {
		const a = await startDeviceA(page);
		const b = await pairDeviceB(a, browser);
		deviceB = b.context;
		// A third owner, an address, which both devices then try to remove.
		await a.popup.getByTestId("manage-flow-done").click();
		await a.popup.getByTestId("manage-add-address").click();
		await a.popup.getByTestId("manage-address-input").fill(EOA);
		await a.popup.getByTestId("manage-address-continue").click();
		await a.popup.getByTestId("manage-address-understood").check();
		await a.popup.getByTestId("manage-address-approve").click();
		await a.popup.getByTestId("manage-flow-done").click({ timeout: 90_000 });
		expect((await readOnChainOwners(a.address)).owners).toHaveLength(3);

		// Device B loads the list with the address in it.
		await signInDeviceB(b);
		const addressOnB = b.wallet.locator("[data-testid=manage-owner-row]", {
			hasText: "Ethereum account",
		});
		await expect(addressOnB).toHaveCount(1, { timeout: 30_000 });

		// Device A removes it first.
		const addressOnA = a.popup.locator("[data-testid=manage-owner-row]", {
			hasText: "Ethereum account",
		});
		await addressOnA.getByTestId("manage-remove").click();
		await a.popup.getByTestId("manage-remove-approve").click();
		await expect(a.popup.getByText("Credential removed")).toBeVisible({
			timeout: 90_000,
		});
		expect((await readOnChainOwners(a.address)).owners).toHaveLength(2);

		// Device B, on its stale list, tries the same removal.
		await addressOnB.getByTestId("manage-remove").click();
		await b.wallet.getByTestId("manage-remove-approve").click();
		await expect(b.wallet.getByTestId("manage-flow-done")).toBeVisible({
			timeout: 90_000,
		});
		await expect(b.wallet.getByText("Nothing was removed")).toBeVisible();
		// Refused before anything was sent: no chain failed, none reverted.
		await expect(
			b.wallet.locator(
				"[data-testid^=manage-chain-progress-][data-state=failed]",
			),
		).toHaveCount(0);
		expect((await readOnChainOwners(a.address)).owners).toHaveLength(2);
	});
});
