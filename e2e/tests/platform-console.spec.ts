import { expect, test } from "@playwright/test";

import { CHAINS } from "../origins.mjs";
import {
	chooseDeployment,
	installWallet,
	openConsole,
	tab,
} from "./console-wallet";

/**
 * The console's tenant registry and platform admins against the real stack (specs/PLATFORM-ADMIN-SPECS.md §14.2 step 3):
 * a platform admin signs in with the console's wallet, sees the tenant registry joined to the devnet
 * paymaster's roster, and takes a tenant through create → suspend → delete without leaving the page.
 *
 * The injected wallet is anvil's account 0, bootstrapped as `admin-console` for the e2e environment
 * (services/wallet-api/src/environments.ts) and holding every paymaster role; its personal_sign is
 * answered by the node.
 */

test.describe("admin console", () => {
	test.beforeEach(async ({ page }) => {
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await page.getByRole("button", { name: /^Connect wallet$/ }).click();
		await expect(
			page.getByRole("button", { name: /^Connected/ }),
		).toBeVisible();
		await page.getByRole("button", { name: /Sign in with wallet/ }).click();
		await expect(page.getByText("admin-console")).toBeVisible();
		await tab(page, /Tenants/).click();
	});

	test("the registry shows the fixture tenants joined to the paymaster roster", async ({
		page,
	}) => {
		for (const slug of ["stock", "byo"]) {
			const row = page.getByTestId(`tenant-row-${slug}`);
			await expect(row).toContainText("active");
			await expect(row).toContainText("registered · enabled");
		}
	});

	test("a tenant is created, suspended and deleted from the console", async ({
		page,
	}) => {
		// a deleted slug is never reusable and this stack's database may outlive a run
		const slug = `console-${Date.now()}`;

		await page.getByRole("button", { name: /Create tenant/ }).click();
		const create = page.getByRole("dialog");
		await create.getByRole("textbox", { name: "Slug" }).fill(slug);
		await create
			.getByRole("textbox", { name: "Wallet origin" })
			.fill(`http://wallet-${slug}.localhost`);
		await create
			.getByRole("textbox", { name: "Display name" })
			.fill("Console E2E");
		await create.getByRole("button", { name: "Create tenant" }).click();
		await expect(create.getByText("These are shown once")).toBeVisible();
		await expect(create.getByText(/^gak_/)).toBeVisible();
		// closing over a key nobody copied asks first
		await create.getByRole("button", { name: "Done" }).click();
		await page
			.getByRole("alertdialog", { name: "Close without copying every key?" })
			.getByRole("button", { name: "Close anyway" })
			.click();

		const row = page.getByTestId(`tenant-row-${slug}`);
		await expect(row).toContainText("not registered");

		await row.click();
		await expect(page).toHaveURL(new RegExp(`/tenants/${slug}$`));
		await page
			.getByTestId("tenant-actions")
			.getByRole("button", { name: /Suspend/ })
			.click();
		const suspend = page.getByRole("dialog", { name: `Suspend ${slug}` });
		await suspend.getByRole("textbox", { name: "Reason" }).fill("console e2e");
		await suspend.getByRole("button", { name: "Suspend" }).click();
		await expect(suspend.getByText(/is suspended/)).toBeVisible();
		await suspend.getByRole("button", { name: "Done" }).click();
		await expect(page.getByTestId("tenant-header")).toContainText("suspended");

		await page
			.getByTestId("tenant-actions")
			.getByRole("button", { name: /Delete/ })
			.click();
		const remove = page.getByRole("dialog", { name: `Delete ${slug}` });
		await expect(
			remove.getByRole("button", { name: "Delete permanently" }),
		).toBeDisabled();
		await remove
			.getByRole("textbox", { name: "Type the slug to confirm" })
			.fill(slug);
		await remove.getByRole("button", { name: "Delete permanently" }).click();
		await expect(page.getByTestId("tenant-history")).toContainText("delete");
		await page.getByRole("link", { name: "Tenants", exact: true }).click();

		// gone from the default list, still there with deleted tenants shown
		await expect(row).toHaveCount(0);
		await page.getByText(/Show deleted tenants/).click();
		await expect(page.getByTestId(`tenant-row-${slug}`)).toContainText(
			"deleted",
		);
	});

	test("on-chain follow-ups, edit and keys: register, disable, re-enable, rename, issue and revoke", async ({
		page,
	}) => {
		const slug = `onchain-${Date.now()}`;
		// copying a shown-once key is what lets its dialog close without asking
		await page
			.context()
			.grantPermissions(["clipboard-read", "clipboard-write"]);
		await page.getByRole("button", { name: /Create tenant/ }).click();
		const create = page.getByRole("dialog");
		await create.getByRole("textbox", { name: "Slug" }).fill(slug);
		await create
			.getByRole("textbox", { name: "Wallet origin" })
			.fill(`http://wallet-${slug}.localhost`);
		await create
			.getByRole("textbox", { name: "Display name" })
			.fill("On-chain E2E");
		await create.getByRole("button", { name: "Create tenant" }).click();
		// admin-console holds TENANT_ADMIN_ROLE on the devnet paymaster, so registering is offered
		await create
			.getByRole("textbox", { name: "Withdrawal address" })
			.fill("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		await create.getByRole("button", { name: "Register on-chain" }).click();
		await expect(create.getByText(/Registered on e2e devnet A/)).toBeVisible({
			timeout: 30_000,
		});
		await create.getByText(/^gak_/).click();
		await expect(create.getByText(/· copied/)).toBeVisible();
		await create.getByRole("button", { name: "Done" }).click();

		const row = page.getByTestId(`tenant-row-${slug}`);
		await expect(row).toContainText("registered · enabled", {
			timeout: 30_000,
		});

		// suspend, and take the offered on-chain disable
		await row.click();
		const header = page.getByTestId("tenant-header");
		const actions = page.getByTestId("tenant-actions");
		await actions.getByRole("button", { name: /Suspend/ }).click();
		const suspend = page.getByRole("dialog", { name: `Suspend ${slug}` });
		await suspend.getByRole("textbox", { name: "Reason" }).fill("on-chain e2e");
		await suspend.getByRole("button", { name: "Suspend" }).click();
		await suspend.getByRole("button", { name: "Disable on-chain" }).click();
		await expect(
			page.getByText(new RegExp(`Disable ${slug} confirmed`)),
		).toBeVisible({ timeout: 30_000 });
		await suspend.getByRole("button", { name: "Done" }).click();
		await expect(header).toContainText("registered · disabled", {
			timeout: 30_000,
		});

		// resume, and re-enable
		await actions.getByRole("button", { name: /Resume/ }).click();
		const resume = page.getByRole("dialog", { name: `Resume ${slug}` });
		await resume.getByRole("button", { name: "Resume" }).click();
		await resume.getByRole("button", { name: "Enable on-chain" }).click();
		await expect(
			page.getByText(new RegExp(`Enable ${slug} confirmed`)),
		).toBeVisible({ timeout: 30_000 });
		await resume.getByRole("button", { name: "Done" }).click();

		// edit: rename
		await actions.getByRole("button", { name: /Edit/ }).click();
		const edit = page.getByRole("dialog", { name: `Edit ${slug}` });
		await edit
			.getByRole("textbox", { name: "Display name" })
			.fill("Renamed in the console");
		// longer than the console's 5 s poll: a refresh while the dialog is open must not wipe the edit
		await page.waitForTimeout(6_000);
		await expect(
			edit.getByRole("textbox", { name: "Display name" }),
		).toHaveValue("Renamed in the console");
		await edit.getByRole("button", { name: "Save" }).click();
		await expect(
			page.getByText("Renamed in the console").first(),
		).toBeVisible();

		// issue a key, then revoke it
		await actions.getByRole("button", { name: /Issue key/ }).click();
		const issue = page.getByRole("dialog", {
			name: `Issue an admin key for ${slug}`,
		});
		await issue.getByRole("textbox", { name: "Label" }).fill("second");
		await issue.getByRole("button", { name: "Issue key" }).click();
		await issue.getByText(/^gak_/).click();
		await expect(issue.getByText(/· copied/)).toBeVisible();
		await issue.getByRole("button", { name: "Done" }).click();
		const revokeButtons = page.getByRole("button", { name: "Revoke" });
		await expect(revokeButtons).toHaveCount(2);
		await revokeButtons.last().click();
		await page
			.getByRole("dialog", { name: /Revoke admin key/ })
			.getByRole("button", { name: "Revoke" })
			.click();
		await expect(revokeButtons).toHaveCount(1);
		await expect(page.getByTestId("tenant-history")).toContainText(
			"admin-key-revoke",
		);
	});

	test("a tenant is registered, funded and given a fee override from its page", async ({
		page,
	}) => {
		const slug = `page-${Date.now()}`;
		await page.getByRole("button", { name: /Create tenant/ }).click();
		const create = page.getByRole("dialog");
		await create.getByRole("textbox", { name: "Slug" }).fill(slug);
		await create
			.getByRole("textbox", { name: "Wallet origin" })
			.fill(`http://wallet-${slug}.localhost`);
		await create
			.getByRole("textbox", { name: "Display name" })
			.fill("Tenant page E2E");
		await create.getByRole("button", { name: "Create tenant" }).click();
		await expect(create.getByText("These are shown once")).toBeVisible();
		await create.getByRole("button", { name: "Done" }).click();
		await page.getByRole("button", { name: "Close anyway" }).click();

		// the list says what is next, and the row opens the tenant's page
		const row = page.getByTestId(`tenant-row-${slug}`);
		await expect(row).toContainText("Register on chain");
		await row.getByRole("link", { name: slug }).click();
		const header = page.getByTestId("tenant-header");
		await expect(header).toContainText("not registered");

		// register from the page
		await page
			.getByRole("textbox", { name: "Withdrawal address" })
			.fill("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		await page
			.getByRole("button", { name: "Register on e2e devnet A" })
			.click();
		await expect(
			page.getByText("Register on e2e devnet A confirmed"),
		).toBeVisible({ timeout: 30_000 });
		await expect(header).toContainText("registered · enabled", {
			timeout: 30_000,
		});

		// the other deployment is read through its own relay, and the ledger is compared
		await expect(
			page.getByTestId(`other-deployment-${CHAINS.b.chainId}`),
		).toContainText("not registered");
		await expect(page.getByTestId("ledger-agreement")).toBeVisible();

		// fund it, then set a fee override: admin-console holds FEE_ADMIN_ROLE and there is no timelock, so Send
		await page.getByRole("textbox", { name: "Fund" }).fill("0.01");
		await page.getByRole("button", { name: "Fund", exact: true }).click();
		await expect(page.getByText("Fund confirmed")).toBeVisible({
			timeout: 30_000,
		});
		await page.getByRole("textbox", { name: "Fee override" }).fill("0.0002");
		await page.getByRole("button", { name: "Set fee override" }).click();
		await expect(page.getByText("Set fee override confirmed")).toBeVisible({
			timeout: 30_000,
		});
		await expect(page.getByText("override", { exact: true })).toBeVisible({
			timeout: 30_000,
		});

		// its history on this chain has each of those, newest first, with who did it
		const onChain = page.getByTestId("tenant-chain-history");
		await expect(onChain).toContainText(`set ${slug}'s fee to 0.0002 ETH`, {
			timeout: 30_000,
		});
		await expect(onChain).toContainText(`funded ${slug} with 0.01 ETH`);
		await expect(onChain).toContainText(
			`registered ${slug}, withdrawing to 0x7099…79C8`,
		);
		await expect(
			onChain.getByTestId("admin-event-TenantRegistered"),
		).toContainText("you");
		const kinds = await onChain
			.locator("[data-testid^=admin-event-]")
			.evaluateAll((rows) =>
				rows.map((row) => row.getAttribute("data-testid")),
			);
		expect(kinds.slice(0, 3)).toEqual([
			"admin-event-TenantFeeChanged",
			"admin-event-TenantFunded",
			"admin-event-TenantRegistered",
		]);
	});

	test("the Overview lists a tenant not registered on this chain by slug, linking to its page", async ({
		page,
	}) => {
		const slug = `attention-${Date.now()}`;
		await page.getByRole("button", { name: /Create tenant/ }).click();
		const create = page.getByRole("dialog");
		await create.getByRole("textbox", { name: "Slug" }).fill(slug);
		await create
			.getByRole("textbox", { name: "Wallet origin" })
			.fill(`http://wallet-${slug}.localhost`);
		await create
			.getByRole("textbox", { name: "Display name" })
			.fill("Attention E2E");
		await create.getByRole("button", { name: "Create tenant" }).click();
		await expect(create.getByText("These are shown once")).toBeVisible();
		await create.getByRole("button", { name: "Done" }).click();
		await page.getByRole("button", { name: "Close anyway" }).click();

		// listed on its own, or, with more than three such tenants, on one line that names the newest
		// first — either way by slug and linking to its page
		await tab(page, /Overview/).click();
		const attention = page.getByTestId("needs-attention");
		await expect(attention).toContainText(slug, { timeout: 30_000 });
		const named = attention.getByRole("link", { name: slug, exact: true });
		if (await named.count()) await named.click();
		else
			await attention
				.locator("[data-testid^=attention-unregistered]")
				.filter({ hasText: `${slug} is not registered on this chain` })
				.getByRole("link", { name: /Register/ })
				.click();
		await expect(page).toHaveURL(new RegExp(`/tenants/${slug}$`));
		await expect(page.getByTestId("tenant-header")).toContainText(
			"not registered",
		);
	});

	test("Admins shows each admin's last sign-in, and ending another of your sessions signs it out", async ({
		page,
		browser,
	}) => {
		// a second sign-in as admin-console, in its own browser
		const other = await browser.newContext();
		const second = await other.newPage();
		try {
			await installWallet(second, { known: [CHAINS.a.chainId] });
			await openConsole(second);
			await chooseDeployment(second, CHAINS.a.chainId);
			await second.getByRole("button", { name: /^Connect wallet$/ }).click();
			await second.getByRole("button", { name: /Sign in with wallet/ }).click();
			await expect(second.getByText("admin-console")).toBeVisible();

			await tab(page, /Admins/).click();
			const me = page.getByTestId("admin-row-admin-console");
			await expect(me.getByTestId("admin-sign-in")).toContainText(
				/\d+ open sessions/,
			);

			// this session is marked and has no End; the newest other open one is the second browser's
			const sessions = page.getByTestId("your-sessions");
			await expect(
				sessions.locator("[data-testid^=session-]").filter({
					hasText: "this session",
				}),
			).toHaveCount(1);
			await expect(
				sessions
					.locator("[data-testid^=session-]")
					.filter({ hasText: "this session" })
					.getByRole("button", { name: "End" }),
			).toHaveCount(0);
			const newestOther = sessions
				.locator("[data-testid^=session-]")
				.filter({ hasText: "open" })
				.filter({ hasNotText: "this session" })
				.first();
			await newestOther.getByRole("button", { name: "End" }).click();
			await expect(page.getByText("Session ended")).toBeVisible();

			// the second browser's next request is refused: it is back at sign-in; this one carries on
			await tab(second, /Admins/).click();
			await expect(
				second.getByRole("button", { name: /Sign in with wallet/ }),
			).toBeVisible({ timeout: 30_000 });
			await page.getByRole("button", { name: "Refresh admins" }).click();
			await expect(me).toBeVisible();
		} finally {
			await other.close();
		}
	});

	test("Health shows what wallet-api sees of each chain it serves", async ({
		page,
	}) => {
		await tab(page, /Health/).click();
		const chains = page.getByTestId("health-chains");
		for (const chainId of [CHAINS.a.chainId, CHAINS.b.chainId]) {
			const chain = chains.getByTestId(`chain-${chainId}`);
			await expect(chain).toContainText("served", { timeout: 30_000 });
			await expect(
				chain.getByTestId(`check-chain-${chainId}-node`),
			).toContainText(/head \d+, \d+s old/);
			await expect(
				chain.getByTestId(`check-chain-${chainId}-bundler`),
			).toContainText("lists the configured EntryPoint");
			// an idle devnet's head is old by design; it is shown, not failed
			await expect(chain).not.toContainText("failing");
		}
		// the console reads it through wallet-api; no node or bundler address is shown
		await expect(chains).not.toContainText("http");

		// the Registry and chain group is wallet-api's drift, compared where the watcher's block is known
		const registry = page.getByTestId("health-registry");
		await expect(registry.getByTestId("check-drift-enabled")).toContainText(
			"On-chain state matches the registry",
		);
		await expect(registry.getByTestId("check-ledger")).toContainText(
			"as wallet-api compared",
		);
	});

	test("admins are added and removed from the console, but never yourself", async ({
		page,
	}) => {
		// a fresh id and address per run: this stack's database may outlive a run
		const id = `admin-run-${Date.now()}`;
		const address = `0x${Date.now().toString(16).padStart(40, "0")}`;

		await tab(page, /Admins/).click();
		for (const bootstrapped of ["admin-e2e", "admin-console", "giovanni"]) {
			await expect(page.getByTestId(`admin-row-${bootstrapped}`)).toBeVisible();
		}
		// the signed-in platform admin has no Remove button on their own row
		const me = page.getByTestId("admin-row-admin-console");
		await expect(me).toContainText("you");
		await expect(me.getByRole("button", { name: /Remove/ })).toHaveCount(0);
		await expect(me).toContainText("You cannot remove yourself");

		await page.getByRole("button", { name: /Add admin/ }).click();
		const add = page.getByRole("dialog", { name: "Add platform admin" });
		await add.getByRole("textbox", { name: "Id" }).fill(id);
		await add.getByRole("textbox", { name: "Wallet address" }).fill(address);
		await add.getByRole("button", { name: "Add admin" }).click();
		const row = page.getByTestId(`admin-row-${id}`);
		await expect(row).toContainText(address);
		await expect(row).toContainText("admin-console");

		await row.getByRole("button", { name: /Remove/ }).click();
		await page
			.getByRole("dialog", { name: `Remove ${id}` })
			.getByRole("button", { name: "Remove admin" })
			.click();
		await expect(row).toHaveCount(0);
		await expect(page.getByTestId("admin-history")).toContainText(`remove`);
		await expect(page.getByTestId("admin-history")).toContainText(id);
	});

	test("a reload signs the admin out, and the session was never stored", async ({
		page,
	}) => {
		const stored = await page.evaluate(
			() =>
				JSON.stringify({ ...localStorage, ...sessionStorage }) +
				document.cookie,
		);
		expect(stored).not.toContain("gps_");
		await page.reload();
		await expect(
			page.getByRole("button", { name: /Sign in with wallet/ }),
		).toBeVisible();
	});
});
