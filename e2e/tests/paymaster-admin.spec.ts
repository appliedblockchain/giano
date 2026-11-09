import { expect, test } from "@playwright/test";
import {
	createPublicClient,
	formatEther,
	getAddress,
	http,
	parseEther,
} from "viem";

import { CHAINS, ORIGINS } from "../origins.mjs";
import {
	chooseDeployment,
	installWallet,
	OPERATOR,
	openConsole,
	signIn,
	signInToPaymaster,
	signOut,
	tab,
	walletCalls,
	walletChain,
} from "./console-wallet";

/**
 * The paymaster console's wallet path, against the real console and the real devnets.
 *
 * Everything the console writes is signed by an injected browser wallet, which means the one part
 * no other suite reaches is also the part hardest to cover: a real extension cannot be driven, and
 * the console's own unit surface stops at the EIP-1193 boundary. So a wallet is scripted into the
 * page — the same shape MetaMask presents, including the rules it enforces on
 * `wallet_addEthereumChain` — and the console is then used exactly as an operator would.
 *
 * Its accounts are anvil's own, unlocked on the devnet, so `eth_sendTransaction` is signed by the
 * node and a write in the console lands on chain for real.
 *
 * This stack's console has the platform API, so it reads nothing until a platform admin signs in:
 * every test that needs the paymaster's state signs in as `admin-console` (anvil account 0) first.
 */

test("connect moves the wallet to the console's chain on its own, with nothing to click", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);

	await page.getByRole("button", { name: /^Connect wallet$/ }).click();

	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();
	expect(await walletChain(page)).toBe(`0x${CHAINS.a.chainId.toString(16)}`);
	expect(await walletCalls(page)).toContain("wallet_switchEthereumChain");
	// The operator was never asked to do it — the old affordance is gone, not merely bypassed.
	await expect(page.getByRole("button", { name: /^Switch to/ })).toHaveCount(0);
	await expect(page.getByText("Wrong network")).toHaveCount(0);
});

test("the wallet card names the account, the network and what that account may do", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await signInToPaymaster(page);

	await page.getByRole("button", { name: /^Connected/ }).click();

	const card = page.getByRole("dialog");
	await expect(card.getByText(OPERATOR)).toBeVisible();
	await expect(
		card.getByText(`chain ${CHAINS.a.chainId}`, { exact: false }),
	).toBeVisible();
	await expect(card.getByText(/on this paymaster/)).toBeVisible();
	// The header's other address is the paymaster's, and is labelled as such rather than left bare.
	// Scoped to the label itself: the tab bar also has a "Paymaster" link.
	await expect(
		page.getByRole("paragraph").filter({ hasText: /^Paymaster$/ }),
	).toBeVisible();
});

test("a chain the wallet has never seen is added with the address published for wallets", async ({
	page,
}) => {
	await installWallet(page, { known: [] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.b.chainId);

	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();

	const added = await page.evaluate(() =>
		window.__wallet.calls.find(
			(call) => call.method === "wallet_addEthereumChain",
		),
	);
	const params = added?.params[0] as { chainId: string; rpcUrls: string[] };
	expect(params.chainId).toBe(`0x${CHAINS.b.chainId.toString(16)}`);
	// walletRpcUrl, not the console's own /rpc/<chainId> proxy path, which no wallet could dial.
	expect(params.rpcUrls[0]).toMatch(/^http:\/\/localhost:8546\/?$/);
	expect(await walletChain(page)).toBe(`0x${CHAINS.b.chainId.toString(16)}`);
});

test("a wallet that will not add a network is answered with the details to add it by hand", async ({
	page,
}) => {
	await installWallet(page, { known: [], refuseAdd: true });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.b.chainId);

	await page.getByRole("button", { name: /^Connect wallet$/ }).click();

	await expect(page.getByText(/Add .* in your wallet/)).toBeVisible();
	// Read out of a serialised JSON-RPC object rather than printed as [object Object].
	await expect(
		page.getByText("this wallet does not add networks"),
	).toBeVisible();
	await expect(page.getByText("Chain ID", { exact: true })).toBeVisible();
	await expect(
		page.getByText(String(CHAINS.b.chainId), { exact: true }),
	).toBeVisible();
	await expect(page.getByText("RPC URL", { exact: true })).toBeVisible();
});

test("a write is signed by the connected wallet and lands on the chain", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();
	await signInToPaymaster(page);

	const chain = createPublicClient({ transport: http(CHAINS.a.rpc) });
	const paymaster = (await page.evaluate(
		async () =>
			(
				await (await fetch("/config.json")).json()
			).deployments[0].sponsorshipPaymaster,
	)) as `0x${string}`;
	const feeOnChain = () =>
		chain.readContract({
			address: paymaster,
			abi: [
				{
					type: "function",
					name: "defaultFeeWei",
					stateMutability: "view",
					inputs: [],
					outputs: [{ type: "uint256" }],
				},
			],
			functionName: "defaultFeeWei",
		});

	// One devnet serves the whole suite, and what this paymaster charges is what the sponsorship
	// tests do their arithmetic against. The fee goes back before this test ends.
	const before = await feeOnChain();

	// Deliberately not waiting on the toast: it outlives the write that raised it, so a second
	// write would match the first one's confirmation and pass without having done anything.
	const setFee = async (value: string) => {
		await tab(page, /Paymaster/).click();
		await page.getByRole("textbox", { name: "New default fee" }).fill(value);
		await page.getByRole("button", { name: "Set default fee" }).click();
	};

	// A value no earlier run would leave behind, so a stale read cannot pass for a fresh write.
	const fee = `0.000${Math.floor(Math.random() * 900) + 100}`;

	try {
		await setFee(fee);

		await expect(page.getByText("Set default fee confirmed")).toBeVisible({
			timeout: 60_000,
		});
		expect(await walletCalls(page)).toContain("eth_sendTransaction");
		// A toast never takes a click: whatever is under its centre gets it. Asked of the browser's own
		// hit test, since Playwright's click would wait for the toast to leave and pass either way.
		const toastHit = await page
			.getByText("Set default fee confirmed")
			.evaluate((title) => {
				const box = (
					title.closest('[data-scope="toast"][data-part="root"]') ?? title
				).getBoundingClientRect();
				const hit = document.elementFromPoint(
					box.left + box.width / 2,
					box.top + box.height / 2,
				);
				return hit?.closest('[data-scope="toast"]') !== null;
			});
		expect(toastHit).toBe(false);
		// The console says it landed; the chain is what settles it.
		await expect.poll(feeOnChain, { timeout: 30_000 }).toBe(parseEther(fee));
	} finally {
		// Even on a failed assertion. This suite runs one worker in file order, so a fee left behind
		// here is a fee the sponsorship tests would do their arithmetic against.
		if ((await feeOnChain()) !== before) {
			await setFee(formatEther(before));
			await expect.poll(feeOnChain, { timeout: 60_000 }).toBe(before);
		}
	}
});

test("the Paymaster tab fills Max from the treasury, and unlocking stake asks before anything is sent", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();
	await signInToPaymaster(page);
	await tab(page, /Paymaster/).click();

	const chain = createPublicClient({ transport: http(CHAINS.a.rpc) });
	const paymaster = (await page.evaluate(
		async () =>
			(
				await (await fetch("/config.json")).json()
			).deployments[0].sponsorshipPaymaster,
	)) as `0x${string}`;
	const treasury = () =>
		chain.readContract({
			address: paymaster,
			abi: [
				{
					type: "function",
					name: "treasury",
					stateMutability: "view",
					inputs: [],
					outputs: [{ type: "uint256" }],
				},
			],
			functionName: "treasury",
		});

	// every card names its role; admin-console holds them all
	await expect(
		page.getByText("FEE_COLLECTOR_ROLE", { exact: true }),
	).toBeVisible();
	await expect(page.getByText("you hold it").first()).toBeVisible();

	// Max is the accrued treasury, exactly. Run alone on a fresh devnet nothing has been sponsored
	// yet, so the treasury is 0 and there is nothing to withdraw: Max is then disabled.
	const amount = page.getByRole("textbox", { name: "Amount" });
	const max = page.getByRole("button", { name: "Max" });
	if ((await treasury()) === 0n) await expect(max).toBeDisabled();
	else {
		await max.click();
		await expect
			.poll(
				async () =>
					(await amount.inputValue()) === formatEther(await treasury()),
			)
			.toBe(true);
	}

	// unlocking stops every bundler accepting the paymaster: it asks first, and Cancel sends nothing
	const sentBefore = (await walletCalls(page)).filter(
		(method) => method === "eth_sendTransaction",
	).length;
	await page.getByRole("button", { name: "Unlock stake" }).click();
	const confirm = page.getByRole("alertdialog", { name: "Unlock the stake" });
	await expect(confirm).toContainText("Bundlers stop accepting this paymaster");
	await confirm.getByRole("button", { name: "Cancel" }).click();
	await expect(confirm).toHaveCount(0);
	expect(
		(await walletCalls(page)).filter(
			(method) => method === "eth_sendTransaction",
		).length,
	).toBe(sentBefore);
});

test("the Paymaster tab adds and removes a signing key, sets each parameter, withdraws a wei of fees and re-locks the stake with 0", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();
	await signInToPaymaster(page);
	await tab(page, /Paymaster/).click();

	const chain = createPublicClient({ transport: http(CHAINS.a.rpc) });
	const paymaster = (await page.evaluate(
		async () =>
			(
				await (await fetch("/config.json")).json()
			).deployments[0].sponsorshipPaymaster,
	)) as `0x${string}`;
	const read = <T>(functionName: string, outputs: string) =>
		chain.readContract({
			address: paymaster,
			abi: [
				{
					type: "function",
					name: functionName,
					stateMutability: "view",
					inputs: [],
					outputs: [{ type: outputs }],
				},
			],
			functionName,
		}) as Promise<T>;
	const confirmed = (label: string) =>
		expect(page.getByText(`${label} confirmed`).last()).toBeVisible({
			timeout: 60_000,
		});

	// a signing key, added and removed again: nothing is left behind for the sponsorship specs
	const key = getAddress(
		`0x${"5e".padEnd(40 - 12, "0")}${Date.now().toString(16).padStart(12, "0")}`,
	);
	await page.getByRole("textbox", { name: "Add a signing key" }).fill(key);
	await page.getByRole("button", { name: "Add signing key" }).click();
	await confirmed("Add signing key");
	const keyRow = page.getByText(key).first();
	await expect(keyRow).toBeVisible({ timeout: 30_000 });
	await page
		.locator("div", { has: page.getByText(key, { exact: true }) })
		.getByRole("button", { name: "Remove" })
		.last()
		.click();
	const removeKey = page.getByRole("alertdialog", {
		name: "Remove a signing key",
	});
	await expect(removeKey).toContainText(key);
	await removeKey.getByRole("button", { name: "Remove key" }).click();
	await confirmed("Remove");
	await expect(page.getByText(key)).toHaveCount(0, { timeout: 30_000 });

	// each parameter moved by one and put back, read from the chain each time
	const gas = await read<number>("postOpGasAllowance", "uint32");
	const penalty = await read<number>("penaltyBps", "uint16");
	const setGas = async (value: number) => {
		await page
			.getByRole("textbox", { name: "New post-op gas allowance" })
			.fill(String(value));
		await page
			.getByRole("button", { name: "Set post-op gas allowance" })
			.click();
		await confirmed("Set post-op gas allowance");
		await expect
			.poll(() => read<number>("postOpGasAllowance", "uint32"))
			.toBe(value);
	};
	const setPenalty = async (value: number) => {
		await page
			.getByRole("textbox", { name: "New unused-gas penalty" })
			.fill(String(value));
		await page.getByRole("button", { name: "Set penalty" }).click();
		await confirmed("Set penalty");
		await expect.poll(() => read<number>("penaltyBps", "uint16")).toBe(value);
	};
	try {
		await setGas(gas + 1);
		await setPenalty(penalty === 0 ? 1 : penalty - 1);
	} finally {
		await setGas(gas);
		await setPenalty(penalty);
	}

	// a wei of accrued fees, where there are any (none on a fresh devnet before sponsorship)
	const treasury = await read<bigint>("treasury", "uint256");
	if (treasury > 0n) {
		await page
			.getByRole("textbox", { name: "Withdraw to" })
			.fill("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		await page
			.getByRole("textbox", { name: "Amount" })
			.fill("0.000000000000000001");
		await page.getByRole("button", { name: "Withdraw fees" }).click();
		const withdraw = page.getByRole("alertdialog", {
			name: "Withdraw from the treasury",
		});
		await expect(withdraw).toContainText(
			"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		);
		await withdraw.getByRole("button", { name: "Withdraw" }).click();
		await confirmed("Withdraw fees");
		await expect
			.poll(() => read<bigint>("treasury", "uint256"))
			.toBe(treasury - 1n);
	}

	// Add stake with 0 re-locks with the delay shown, which is the on-chain one: no funds move
	const locked = page.getByText("Staked and locked");
	await expect(locked).toBeVisible();
	await page.getByRole("textbox", { name: "Add stake" }).fill("0");
	await page.getByRole("button", { name: "Add stake", exact: true }).click();
	await confirmed("Add stake");
	await expect(locked).toBeVisible();
});

test("the Roles tab grants, rotates and revokes a role, each change landing on chain", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await page.getByRole("button", { name: /^Connect wallet$/ }).click();
	await expect(page.getByRole("button", { name: /^Connected/ })).toBeVisible();
	await signInToPaymaster(page);
	await tab(page, /Roles/).click();

	// the tab renders once the paymaster is read, which takes longer while the whole suite runs
	await expect(page.getByTestId("default-admin")).toContainText(
		"held by nobody",
		{
			timeout: 30_000,
		},
	);
	const row = page.getByTestId("role-PAUSER_ROLE");
	await expect(row).toContainText("May halt acceptance of new sponsorships");

	// two fresh addresses, so a run leaves nothing behind for the next one
	const stamp = Date.now().toString(16);
	const first = `0x${"a1".padEnd(40 - stamp.length, "0")}${stamp}`;
	const second = `0x${"b2".padEnd(40 - stamp.length, "0")}${stamp}`;
	const holder = (address: string) => row.getByTestId(`holder-${address}`);

	await page.getByLabel("Role", { exact: true }).selectOption("PAUSER_ROLE");
	await page.getByRole("textbox", { name: "Grant to" }).fill(first);
	await page.getByRole("button", { name: "Grant", exact: true }).click();
	await expect(holder(first)).toBeVisible({ timeout: 30_000 });

	// a rotation grants the new holder before it revokes the old one
	await page.getByLabel("From").selectOption({ label: getAddress(first) });
	// rotating a holder to itself would leave the role with nobody: refused before the wallet
	await page.getByRole("textbox", { name: "To", exact: true }).fill(first);
	await expect(page.getByText("rotating to itself would leave")).toBeVisible();
	await expect(
		page.getByRole("button", { name: "Rotate", exact: true }),
	).toBeDisabled();
	await page.getByRole("textbox", { name: "To", exact: true }).fill(second);
	// Rotate revokes, so it asks first, naming who gains the role and who loses it
	await page.getByRole("button", { name: "Rotate", exact: true }).click();
	const rotate = page.getByRole("alertdialog", { name: "Rotate PAUSER_ROLE" });
	await expect(rotate).toContainText(second, { ignoreCase: true });
	await expect(rotate).toContainText(first, { ignoreCase: true });
	await rotate.getByRole("button", { name: "Rotate" }).click();
	await expect(holder(second)).toBeVisible({ timeout: 30_000 });
	await expect(holder(first)).toHaveCount(0, { timeout: 30_000 });

	await holder(second).getByRole("button", { name: "Revoke" }).click();
	const confirm = page.getByRole("alertdialog", { name: "Revoke PAUSER_ROLE" });
	await expect(confirm).toContainText(
		"will no longer be able to halt acceptance",
	);
	await confirm.getByRole("button", { name: "Revoke" }).click();
	await expect(holder(second)).toHaveCount(0, { timeout: 30_000 });
});

/**
 * Who may read (openspec platform-console-access, platform-chain-reads, spa-container-runtime): the
 * hosted console reads the chain only through wallet-api's platform relay, with a platform admin
 * session, and its own nginx no longer proxies the keyed RPC URL to anyone who asks.
 */
test("Health says once that no timelock is configured, and names the implementation's release", async ({
	page,
}) => {
	await installWallet(page, { known: [CHAINS.a.chainId] });
	await openConsole(page);
	await chooseDeployment(page, CHAINS.a.chainId);
	await signInToPaymaster(page);
	await tab(page, /Health/).click();

	const keys = page.getByTestId("health-keys");
	await expect(keys.getByTestId("check-timelock")).toContainText(
		"no timelock configured",
	);
	await expect(keys.getByTestId("check-timelock")).toContainText("warning");
	await expect(keys.getByTestId("check-implementation")).toContainText(
		"release v3",
	);
	// One warning for the deployment, not one per holder asking to verify it.
	await expect(page.getByText(/verify this is the timelock/)).toHaveCount(0);
	await expect(keys.getByTestId("check-role-ROLE_ADMIN")).toHaveCount(0);
});

test.describe("access", () => {
	const PLATFORM_RPC = /\/api\/v1\/platform\/rpc\/(\d+)$/;

	test("an anonymous visit shows only the sign-in view and reads nothing from the chain", async ({
		page,
	}) => {
		const reads: string[] = [];
		page.on("request", (request) => {
			if (/\/rpc\//.test(request.url())) reads.push(request.url());
		});
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);

		await expect(tab(page, /Overview/)).toHaveCount(0);
		await expect(page.getByText("Reading the paymaster…")).toHaveCount(0);
		expect(reads).toEqual([]);
	});

	test("every chain read after sign-in goes to the platform relay with the session", async ({
		page,
	}) => {
		const reads: { url: string; authorization: string | undefined }[] = [];
		let pending = 0;
		const isRead = (url: string) => /\/rpc\//.test(url);
		page.on("request", (request) => {
			if (!isRead(request.url())) return;
			pending++;
			reads.push({
				url: request.url(),
				authorization: request.headers().authorization,
			});
		});
		for (const done of ["requestfinished", "requestfailed"] as const)
			page.on(done, (request) => {
				if (isRead(request.url())) pending--;
			});
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signInToPaymaster(page);

		// One refresh, counted on its own: what a session spends per poll (PLATFORM_RPC_RATE_LIMIT_PER_MINUTE).
		const before = reads.length;
		await page.getByRole("button", { name: "Refresh" }).click();
		// Settled: nothing in flight, and nothing new for a moment.
		await expect
			.poll(
				async () => {
					const seen = reads.length;
					await page.waitForTimeout(750);
					return pending === 0 && reads.length === seen && seen > before;
				},
				{ timeout: 15_000 },
			)
			.toBe(true);
		test.info().annotations.push({
			type: "reads per refresh",
			description: String(reads.length - before),
		});

		expect(reads.length).toBeGreaterThan(0);
		for (const read of reads) {
			expect(read.url).toMatch(PLATFORM_RPC);
			expect(read.url).toContain(`/${CHAINS.a.chainId}`);
			expect(read.authorization).toMatch(/^Bearer gps_/);
		}
	});

	test("one session serves every tab, and signing out ends it", async ({
		page,
	}) => {
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signInToPaymaster(page);

		await tab(page, /Tenants/).click();
		await expect(page.getByTestId("tenant-row-stock")).toBeVisible();
		await tab(page, /Overview/).click();
		await expect(tab(page, /Overview/)).toHaveAttribute("aria-current", "page");
		await expect(
			page.getByRole("button", { name: /Sign in with wallet/ }),
		).toHaveCount(0);

		await signOut(page);
		await expect(
			page.getByRole("button", { name: /Sign in with wallet/ }),
		).toBeVisible();
		await expect(tab(page, /Overview/)).toHaveCount(0);
	});

	test("disconnecting the wallet also ends the session it signed", async ({
		page,
	}) => {
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signInToPaymaster(page);

		await page.getByRole("button", { name: /^Connected/ }).click();
		await page.getByRole("button", { name: "Disconnect and sign out" }).click();
		await expect(
			page.getByRole("button", { name: /^Connect wallet$/ }),
		).toBeVisible();
		await expect(
			page.getByRole("button", { name: /Sign in with wallet/ }),
		).toBeVisible();
		await expect(tab(page, /Overview/)).toHaveCount(0);
	});

	test("each tab has its own URL, which survives a reload and a fresh sign-in", async ({
		page,
	}) => {
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signInToPaymaster(page);

		await tab(page, /Timelock/).click();
		await expect(page).toHaveURL(/\/timelock$/);
		await page.reload();
		await signIn(page);
		await expect(tab(page, /Timelock/)).toHaveAttribute("aria-current", "page");

		await page.goBack();
		await expect(page).toHaveURL(/\/$/);
		await expect(tab(page, /Overview/)).toHaveAttribute("aria-current", "page");
	});

	test("a tenant has its own URL, and an unknown path says there is no such page", async ({
		page,
	}) => {
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await page.goto(`${ORIGINS.paymasterAdmin}/tenants/byo`);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signIn(page);
		await expect(page.getByTestId("tenant-header")).toContainText("byo");

		await page.goto(`${ORIGINS.paymasterAdmin}/settings`);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signIn(page);
		await expect(page.getByText("No such page")).toBeVisible();
		await page.getByRole("link", { name: "Go to the Overview" }).click();
		await expect(tab(page, /Overview/)).toHaveAttribute("aria-current", "page");
	});

	test("Stay signed in replaces a session about to end, keeping what was typed", async ({
		page,
	}) => {
		// The first sign-in's session is made to end in 100 seconds, inside the 2-minute warning;
		// the second, from Stay signed in, is the server's own.
		let shortened = false;
		await page.route("**/api/v1/platform/auth/verify", async (route) => {
			const response = await route.fetch();
			if (shortened) return route.fulfill({ response });
			shortened = true;
			const json = await response.json();
			json.expiresAt = new Date(Date.now() + 100_000).toISOString();
			await route.fulfill({ response, json });
		});
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signInToPaymaster(page);

		await tab(page, /Tenants/).click();
		await page.getByLabel("Search tenants").fill("half-typed");
		const warning = page
			.getByRole("status")
			.filter({ hasText: "Your session ends in" });
		await expect(warning).toBeVisible({ timeout: 15_000 });

		await warning.getByRole("button", { name: "Stay signed in" }).click();
		await expect(warning).toHaveCount(0, { timeout: 30_000 });
		await expect(
			page.getByRole("button", { name: "Platform admin session" }),
		).toContainText(/([23]\d) min left/);
		await expect(page.getByLabel("Search tenants")).toHaveValue("half-typed");
	});

	test("every tab fits a 390 px phone, with wide tables scrolling inside their own box", async ({
		page,
	}) => {
		await page.setViewportSize({ width: 390, height: 844 });
		await installWallet(page, { known: [CHAINS.a.chainId] });
		await openConsole(page);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signInToPaymaster(page);
		for (const name of [
			/Overview/,
			/Tenants/,
			/Paymaster/,
			/Roles/,
			/Timelock/,
			/Activity/,
			/Health/,
			/Admins/,
		]) {
			// the tab bar scrolls sideways within itself, so the link can be off screen: scroll to it
			const link = tab(page, name);
			await link.scrollIntoViewIfNeeded();
			await link.click();
			await page.waitForTimeout(1_500);
			const overflow = await page.evaluate(
				() =>
					document.documentElement.scrollWidth -
					document.documentElement.clientWidth,
			);
			expect(overflow, `${name} scrolls the page sideways`).toBeLessThanOrEqual(
				0,
			);
		}
	});

	test("the platform relay refuses a caller with no session, and the console proxies no RPC", async ({
		request,
	}) => {
		const body = {
			jsonrpc: "2.0",
			id: 1,
			method: "eth_blockNumber",
			params: [],
		};
		const relay = await request.post(
			`${ORIGINS.paymasterAdmin}/api/v1/platform/rpc/${CHAINS.a.chainId}`,
			{ data: body },
		);
		expect(relay.status()).toBe(401);

		const legacy = await request.post(
			`${ORIGINS.paymasterAdmin}/rpc/${CHAINS.a.chainId}`,
			{ data: body },
		);
		expect(legacy.status()).toBe(405);

		const config = await (
			await request.get(`${ORIGINS.paymasterAdmin}/config.json`)
		).json();
		for (const deployment of config.deployments)
			expect(deployment.rpcUrl).toBe(
				`/api/v1/platform/rpc/${deployment.chainId}`,
			);
	});

	test("security headers are on every response, including config and assets", async ({
		request,
	}) => {
		const index = await (await request.get(ORIGINS.paymasterAdmin)).text();
		const asset = /\/assets\/[^"]+\.js/.exec(index)?.[0];
		expect(asset).toBeDefined();

		for (const path of ["/", "/config.json", asset as string, "/some/route"]) {
			const headers = (
				await request.get(`${ORIGINS.paymasterAdmin}${path}`)
			).headers();
			expect(headers["x-frame-options"], path).toBe("DENY");
			expect(headers["content-security-policy"], path).toContain(
				"frame-ancestors 'none'",
			);
			expect(headers["x-content-type-options"], path).toBe("nosniff");
			expect(headers["referrer-policy"], path).toBe("no-referrer");
		}
	});
});
