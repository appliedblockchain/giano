/**
 * Smoke test of a deployed environment, through its reference dApp (services/custom-example).
 * Run it with smoke/run.mjs, which takes the targets as --target arguments; see that file.
 *
 * Per target, on each chain the dApp serves: a new passkey account, one sponsored transaction
 * (mint the default token, or send 0 ETH to self where the dApp has no default token), then on
 * chain: the account has code, and the transaction succeeded with a paymaster. Finally, the account
 * address is the same on every chain (a passkey derives one address everywhere, MC-22).
 *
 * Everything about the environment is read from the dApp's runtime config (window.__GIANO_CONFIG__,
 * rendered from /config.js): the wallet origin, the chains, their RPC and default token.
 */
import { expect, type Page, test } from "@playwright/test";
import * as viemChains from "viem/chains";
import {
	addVirtualAuthenticator,
	openActionPopup,
	openWalletPopup,
	TENANTS,
	trackResidentCredentials,
	type VirtualCredential,
} from "../tests/helpers";

type DappChain = {
	chainId: number;
	name: string;
	rpcUrl: string;
	defaultToken?: string;
};
type DappConfig = { walletUrl: string; chains: DappChain[] };

/** The fields of the dApp's ledger entry (services/custom-example/src/lib/ledger.ts) read here. */
type LedgerEntry = {
	id: string;
	chainId: number;
	method: string;
	status: string;
	account?: string;
	userOpHash?: string;
	txHash?: string;
	receipt?: { paymaster?: string; success?: boolean };
	error?: { message?: string };
	note?: string;
};

type Result = {
	chain: string;
	action: string;
	account: string;
	userOpHash: string;
	txHash: string;
	paymaster: string;
	explorer?: string;
};

const targets: string[] = JSON.parse(process.env.SMOKE_TARGETS || "[]");
const onlyChains = (process.env.SMOKE_CHAINS ?? "")
	.split(",")
	.filter(Boolean)
	.map(Number);
const allowProduction = process.env.SMOKE_ALLOW_PRODUCTION === "1";

// Both wallet UIs a tenant can serve: Giano's stock wallet-web, and the BYO fixture.
const either = (a: string, b: string) => new RegExp(`^(${a}|${b})$`);
const CONNECT = either(TENANTS.stock.ui.connect, TENANTS.byo.ui.connect);
const APPROVE = either(TENANTS.stock.ui.approveTx, TENANTS.byo.ui.approveTx);

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const TERMINAL = new Set([
	"confirmed",
	"failed",
	"refused",
	"timed-out",
	"violation",
]);
/**
 * The dApp persists an in-flight entry as `timed-out` with this note (saveLedger in
 * services/custom-example/src/lib/ledger.ts), for the case where the page goes away. While the page
 * is open, that stored value only means "not settled yet", so it is not an outcome.
 */
const IN_FLIGHT_NOTE = "page unloaded before the outcome arrived";
const settled = (entry: LedgerEntry) =>
	TERMINAL.has(entry.status) &&
	!(entry.status === "timed-out" && entry.note === IN_FLIGHT_NOTE);

const knownChains = Object.values(viemChains).filter(
	(chain): chain is (typeof viemChains)[keyof typeof viemChains] =>
		typeof chain === "object" && chain !== null && "id" in chain,
);

if (targets.length === 0) {
	test("smoke needs a target", () => {
		throw new Error(
			"No target. Run: pnpm -F @appliedblockchain/giano-e2e smoke --target <dApp URL>",
		);
	});
}

for (const target of targets) {
	test(`smoke: ${target}`, async ({ page }) => {
		await page.goto(target);
		const config = await page.evaluate(
			() =>
				(window as unknown as { __GIANO_CONFIG__?: unknown }).__GIANO_CONFIG__,
		);
		const { walletUrl, chains } = parseConfig(target, config);
		const selected = onlyChains.length
			? onlyChains.map((id) => {
					const chain = chains.find((candidate) => candidate.chainId === id);
					if (!chain)
						throw new Error(
							`${target} does not serve chain ${id}; it serves ${chains.map((c) => c.chainId).join(", ")}`,
						);
					return chain;
				})
			: chains;
		for (const chain of selected) {
			const known = knownChains.find(
				(candidate) => candidate.id === chain.chainId,
			);
			if (!known?.testnet && !allowProduction)
				throw new Error(
					`chain ${chain.chainId} (${chain.name}) is not a known testnet; pass --allow-production to run there`,
				);
		}
		console.log(`target ${target}: wallet ${walletUrl}`);

		let credentials: VirtualCredential[] = [];
		const results: Result[] = [];
		for (const [index, chain] of selected.entries()) {
			await test.step(`${chain.name} (${chain.chainId})`, async () => {
				if (index === 0) {
					if (chain.chainId !== chains[0].chainId)
						await selectChain(page, chain);
					const popup = await openWalletPopup(page, "[data-testid=connect]");
					const { cdp } = await addVirtualAuthenticator(popup);
					credentials = trackResidentCredentials(cdp);
					await popup.getByRole("button", { name: CONNECT }).click();
					await expect(page.getByTestId("account")).toBeVisible({
						timeout: 60_000,
					});
				} else {
					await selectChain(page, chain);
					const popup = await openActionPopup(
						page,
						"[data-testid=connect-chain]",
						credentials,
					);
					await popup.getByRole("button", { name: CONNECT }).click();
					await popup.waitForEvent("close", { timeout: 60_000 });
				}

				const before = new Set(
					(await readLedger(page, walletUrl)).map((e) => e.id),
				);
				const action = chain.defaultToken
					? await mintDefaultToken(page, chain.defaultToken, credentials)
					: await sendToSelf(page, credentials);

				const entry = await waitForEntry(
					page,
					walletUrl,
					chain.chainId,
					before,
				);
				// The whole entry on failure: its error, note and hashes say where it stopped.
				expect(entry.status, JSON.stringify(entry, null, 2)).toBe("confirmed");
				expect(entry.receipt?.success, "user operation succeeded").toBe(true);
				const paymaster = entry.receipt?.paymaster ?? ZERO_ADDRESS;
				expect(paymaster.toLowerCase(), "paid by a paymaster").not.toBe(
					ZERO_ADDRESS,
				);
				const account = entry.account ?? "";
				const txHash = entry.txHash ?? "";
				expect(account).toMatch(/^0x[0-9a-fA-F]{40}$/);
				expect(txHash).toMatch(/^0x[0-9a-fA-F]{64}$/);

				// On chain, through the dApp's own RPC for this chain.
				const code = await rpc<string>(page, chain.rpcUrl, "eth_getCode", [
					account,
					"latest",
				]);
				expect(code, "account deployed").toMatch(/^0x[0-9a-fA-F]+$/);
				expect(code).not.toBe("0x");
				const receipt = await rpc<{ status?: string } | null>(
					page,
					chain.rpcUrl,
					"eth_getTransactionReceipt",
					[txHash],
				);
				expect(receipt?.status, "transaction status").toBe("0x1");

				const known = knownChains.find(
					(candidate) => candidate.id === chain.chainId,
				);
				const explorer = known?.blockExplorers?.default.url;
				const result: Result = {
					chain: `${chain.name} (${chain.chainId})`,
					action,
					account,
					userOpHash: entry.userOpHash ?? "",
					txHash,
					paymaster,
					explorer: explorer ? `${explorer}/tx/${txHash}` : undefined,
				};
				results.push(result);
				console.log(
					`  ✓ ${result.chain}: ${action}; account ${account}; userOp ${result.userOpHash}; tx ${txHash}; paymaster ${paymaster}${result.explorer ? `; ${result.explorer}` : ""}`,
				);
				test.info().annotations.push({
					type: result.chain,
					description: JSON.stringify(result),
				});
			});
		}

		const accounts = new Set(
			results.map((result) => result.account.toLowerCase()),
		);
		expect(accounts.size, "one account address on every chain").toBe(1);
	});
}

function parseConfig(target: string, config: unknown): DappConfig {
	const candidate = config as Partial<DappConfig> | undefined;
	if (
		!candidate ||
		typeof candidate.walletUrl !== "string" ||
		!Array.isArray(candidate.chains) ||
		candidate.chains.length === 0
	)
		throw new Error(
			`${target} has no usable runtime config (window.__GIANO_CONFIG__ from /config.js): is it a Giano reference dApp?`,
		);
	return {
		walletUrl: candidate.walletUrl.replace(/\/$/, ""),
		chains: candidate.chains.map((chain) => ({
			...chain,
			defaultToken: chain.defaultToken || undefined,
		})),
	};
}

async function selectChain(page: Page, chain: DappChain): Promise<void> {
	await page.getByTestId("tab-setup").click();
	await page
		.getByTestId("chain-selector")
		.getByText(chain.name, { exact: true })
		.click();
}

async function mintDefaultToken(
	page: Page,
	token: string,
	credentials: VirtualCredential[],
): Promise<string> {
	await page.getByTestId("tab-tokens").click();
	const field = page.getByPlaceholder("0x…").first();
	if ((await field.inputValue()).toLowerCase() !== token.toLowerCase())
		await field.fill(token);
	await page.getByTestId("load-token").click();
	await page.getByLabel("Action").selectOption("mint");
	await expect(page.getByTestId("erc20-run")).toBeEnabled();
	await approveIn(
		await openActionPopup(page, "[data-testid=erc20-run]", credentials),
	);
	return `mint ${token}`;
}

async function sendToSelf(
	page: Page,
	credentials: VirtualCredential[],
): Promise<string> {
	await page.getByTestId("tab-transactions").click();
	await approveIn(
		await openActionPopup(page, "[data-testid=send]", credentials),
	);
	return "send 0 ETH to self";
}

async function approveIn(popup: Page): Promise<void> {
	await popup.getByRole("button", { name: APPROVE }).click({ timeout: 60_000 });
}

/** The dApp's own ledger, as it persists it (ledgerStorageKey in services/custom-example). */
async function readLedger(
	page: Page,
	walletUrl: string,
): Promise<LedgerEntry[]> {
	return page.evaluate((key) => {
		try {
			const parsed = JSON.parse(localStorage.getItem(key) ?? "{}");
			return Array.isArray(parsed.entries) ? parsed.entries : [];
		} catch {
			return [];
		}
	}, `giano-demo:ledger:${walletUrl}`);
}

/** The transaction this step started: the new eth_sendTransaction entry on this chain, once settled. */
async function waitForEntry(
	page: Page,
	walletUrl: string,
	chainId: number,
	before: Set<string>,
): Promise<LedgerEntry> {
	let found: LedgerEntry | undefined;
	await expect
		.poll(
			async () => {
				found = (await readLedger(page, walletUrl)).find(
					(entry) =>
						!before.has(entry.id) &&
						entry.chainId === chainId &&
						entry.method === "eth_sendTransaction",
				);
				return found && settled(found) ? found.status : "pending";
			},
			{ timeout: 240_000, intervals: [2_000] },
		)
		.not.toBe("pending");
	return found as LedgerEntry;
}

async function rpc<T>(
	page: Page,
	rpcUrl: string,
	method: string,
	params: unknown[],
): Promise<T> {
	const response = await page.evaluate(
		async ({ rpcUrl, method, params }) => {
			const res = await fetch(rpcUrl, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
			});
			return res.json();
		},
		{ rpcUrl, method, params },
	);
	if (response.error)
		throw new Error(`${method} failed: ${JSON.stringify(response.error)}`);
	return response.result as T;
}
