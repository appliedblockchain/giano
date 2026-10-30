import { expect, test } from "@playwright/test";
import { createPublicClient, formatEther, http, parseEther } from "viem";

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
		await page.getByLabel("New default fee (ETH)").fill(value);
		await page.getByRole("button", { name: /^Set$/ }).first().click();
	};

	// A value no earlier run would leave behind, so a stale read cannot pass for a fresh write.
	const fee = `0.000${Math.floor(Math.random() * 900) + 100}`;

	try {
		await setFee(fee);

		await expect(page.getByText("Set default fee confirmed")).toBeVisible({
			timeout: 60_000,
		});
		expect(await walletCalls(page)).toContain("eth_sendTransaction");
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

/**
 * Who may read (openspec platform-console-access, platform-chain-reads, spa-container-runtime): the
 * hosted console reads the chain only through wallet-api's platform relay, with a platform admin
 * session, and its own nginx no longer proxies the keyed RPC URL to anyone who asks.
 */
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
		await expect(page.getByRole("dialog")).toContainText("byo");

		await page.goto(`${ORIGINS.paymasterAdmin}/settings`);
		await chooseDeployment(page, CHAINS.a.chainId);
		await signIn(page);
		await expect(page.getByText("No such page")).toBeVisible();
		await page.getByRole("link", { name: "Go to the Overview" }).click();
		await expect(tab(page, /Overview/)).toHaveAttribute("aria-current", "page");
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
