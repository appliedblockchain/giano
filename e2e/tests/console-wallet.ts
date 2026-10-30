import { expect, type Page } from "@playwright/test";

import { CHAINS, ORIGINS } from "../origins.mjs";

/**
 * The scripted browser wallet the paymaster console is driven with, shared by the console's
 * specs (paymaster-admin.spec.ts, platform-console.spec.ts).
 *
 * A real extension cannot be driven, so an EIP-1193 wallet is injected before any page script
 * runs, shaped like MetaMask where the console's behaviour depends on it. Its accounts are anvil's
 * own, unlocked on the devnet: anything it does not answer itself — eth_sendTransaction,
 * personal_sign — is sent to the node and signed there.
 *
 * Not through the console's own read path: a wallet dials its own RPC, and the console's is
 * wallet-api's platform relay, which forwards reads only and only for a signed-in platform admin.
 * So the wallet posts to `/__wallet-rpc/<chainId>` on the page's origin — same-origin, which the
 * console's CSP allows — and Playwright answers it from the test runner by forwarding to the devnet.
 */

/** anvil's first account, which holds every role on the devnet paymaster. */
export const OPERATOR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/** A chain neither devnet uses, so a connection always has to move the wallet. */
export const ELSEWHERE = "0x1";

export type WalletOptions = {
	/** Chains the wallet already knows. Anything else must go through `wallet_addEthereumChain`. */
	known?: number[];
	/** Make the wallet refuse to add a network, the way one that only holds fixed networks does. */
	refuseAdd?: boolean;
};

export type WalletCall = { method: string; params: unknown[] };

declare global {
	interface Window {
		__wallet: { calls: WalletCall[]; chainId: () => string };
	}
}

/**
 * Installs an EIP-1193 wallet before any page script runs.
 *
 * Modelled on MetaMask where the console's behaviour depends on it: 4902 for a chain it does not
 * know, MetaMask's HTTPS-or-localhost rule on the RPC URL of a network it is asked to add, and a
 * serialised `{ code, message }` object rather than an `Error` — which is what actually crosses an
 * extension boundary, and what the console has to read a reason out of.
 */
export async function installWallet(
	page: Page,
	{ known = [], refuseAdd = false }: WalletOptions = {},
) {
	await page.addInitScript(
		({ operator, elsewhere, known, refuseAdd }) => {
			const knownChains = new Set(known.map((id) => `0x${id.toString(16)}`));
			const listeners: Record<string, ((payload: unknown) => void)[]> = {};
			const calls: { method: string; params: unknown[] }[] = [];
			let chainId = elsewhere;

			const emit = (event: string, payload: unknown) => {
				for (const fn of listeners[event] ?? []) fn(payload);
			};

			const forward = async (method: string, params: unknown[]) => {
				const response = await fetch(
					`${location.origin}/__wallet-rpc/${parseInt(chainId, 16)}`,
					{
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({
							jsonrpc: "2.0",
							id: Date.now(),
							method,
							params,
						}),
					},
				);
				const body = await response.json();
				if (body.error)
					throw { code: body.error.code, message: body.error.message };
				return body.result;
			};

			const provider = {
				isMetaMask: true,
				async request({
					method,
					params = [],
				}: {
					method: string;
					params?: unknown[];
				}) {
					calls.push({ method, params });
					switch (method) {
						case "eth_requestAccounts":
						case "eth_accounts":
							return [operator];
						case "eth_chainId":
							return chainId;
						case "wallet_switchEthereumChain": {
							const target = (params[0] as { chainId: string }).chainId;
							if (!knownChains.has(target))
								throw {
									code: 4902,
									message: `Unrecognized chain ID ${target}.`,
								};
							chainId = target;
							emit("chainChanged", target);
							return null;
						}
						case "wallet_addEthereumChain": {
							const added = params[0] as { chainId: string; rpcUrls: string[] };
							if (refuseAdd)
								throw {
									code: -32601,
									message: "this wallet does not add networks",
								};
							const url = new URL(added.rpcUrls[0]);
							if (
								url.protocol !== "https:" &&
								url.hostname !== "localhost" &&
								url.hostname !== "127.0.0.1"
							) {
								throw {
									code: -32602,
									message: `Expected an array with at least one valid string HTTPS url 'rpcUrls', Received:\n${added.rpcUrls[0]}`,
								};
							}
							knownChains.add(added.chainId);
							return null;
						}
						default:
							return forward(method, params);
					}
				},
				on(event: string, fn: (payload: unknown) => void) {
					listeners[event] = [...(listeners[event] ?? []), fn];
				},
				removeListener(event: string, fn: (payload: unknown) => void) {
					listeners[event] = (listeners[event] ?? []).filter(
						(other) => other !== fn,
					);
				},
			};

			Object.defineProperty(window, "ethereum", {
				value: provider,
				writable: true,
				configurable: true,
			});
			Object.defineProperty(window, "__wallet", {
				value: { calls, chainId: () => chainId },
				writable: false,
				configurable: true,
			});
		},
		{ operator: OPERATOR, elsewhere: ELSEWHERE, known, refuseAdd },
	);
	// The wallet's own connection to the chain, outside the page — see the header.
	await page.route(/\/__wallet-rpc\/(\d+)$/, async (route) => {
		const chainId = Number(/(\d+)$/.exec(route.request().url())?.[1]);
		const chain = Object.values(CHAINS).find((c) => c.chainId === chainId);
		if (!chain) return route.fulfill({ status: 404 });
		const response = await fetch(chain.rpc, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: route.request().postData() ?? "",
		});
		await route.fulfill({
			status: response.status,
			contentType: "application/json",
			body: await response.text(),
		});
	});
}

export const walletCalls = (page: Page) =>
	page.evaluate(() => window.__wallet.calls.map((call) => call.method));
export const walletChain = (page: Page) =>
	page.evaluate(() => window.__wallet.chainId());

/** Picks a deployment in the header, which the console offers only when it administers several. */
export async function chooseDeployment(page: Page, chainId: number) {
	const picker = page.getByLabel("Deployment");
	const value = await picker.evaluate((element, wanted) => {
		const option = [...(element as HTMLSelectElement).options].find(
			(candidate) => candidate.textContent?.includes(`chain ${wanted}`),
		);
		if (!option)
			throw new Error(`the console offers no deployment on chain ${wanted}`);
		return option.value;
	}, chainId);
	await picker.selectOption(value);
	await expect(
		page.getByRole("button", { name: /^Connect wallet$/ }),
	).toBeVisible();
}

/**
 * Opens the console, which in this stack has the platform API — so it opens on the sign-in view,
 * having read nothing from the chain.
 */
export async function openConsole(page: Page) {
	await page.goto(ORIGINS.paymasterAdmin);
	await expect(
		page.getByRole("button", { name: /Sign in with wallet/ }),
	).toBeVisible();
}

/**
 * Signs in as the console's wallet — anvil account 0, bootstrapped as `admin-console` — connecting
 * it first if needed. The tab bar renders once the first chain read lands.
 */
export async function signIn(page: Page) {
	await page.getByRole("button", { name: /Sign in with wallet/ }).click();
	await expect(page.getByText("admin-console")).toBeVisible();
}

export async function signInToPaymaster(page: Page) {
	await signIn(page);
	await expect(tab(page, /Overview/)).toBeVisible();
}

/** A tab in the console's one tab bar. Links, not ARIA tabs: each is a page with its own URL. */
export const tab = (page: Page, name: RegExp) =>
	page.getByRole("navigation", { name: "Console" }).getByRole("link", { name });

/** Signs out through the session menu in the header. */
export async function signOut(page: Page) {
	await page.getByRole("button", { name: "Platform admin session" }).click();
	await page.getByRole("button", { name: /^Sign out$/ }).click();
}
