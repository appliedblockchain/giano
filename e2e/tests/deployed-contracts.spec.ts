import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Page, test } from "@playwright/test";
import {
	type Address,
	createPublicClient,
	createWalletClient,
	encodeFunctionData,
	getAbiItem,
	type Hex,
	http,
	keccak256,
	parseAbi,
	toHex,
} from "viem";
import { entryPoint09Abi } from "viem/account-abstraction";
import { privateKeyToAccount } from "viem/accounts";
import { ORIGINS } from "../origins.mjs";
import {
	connectWallet,
	openActionPopup,
	TENANTS,
	type VirtualCredential,
} from "./helpers";

/**
 * Sponsorship for contracts an app deploys at run time (PS-4).
 *
 * Some apps deploy a contract for every payment: an escrow, as an EIP-1167 clone made by a
 * permissionless factory that keeps no record of what it deployed. The tenant cannot name those
 * escrows in its sponsorship rules in advance, but it can predict each address before the
 * deployment. These tests record what sponsorship covers:
 *
 * - the call to an allow-listed factory that deploys an escrow;
 * - a later call to that escrow, which no rule names;
 * - the same call once the tenant allows the escrow's predicted address.
 *
 * The fixture is `GianoTestEscrowFactory` (packages/contracts/src/testing/), deployed here from its
 * committed artifact by an anvil account no other spec uses.
 */

const repoRoot = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"..",
	"..",
);
const FACTORY = JSON.parse(
	fs.readFileSync(
		path.join(repoRoot, "packages/contracts/fixtures/test-escrow-factory.json"),
		"utf8",
	),
) as { creationCode: Hex };
const ADDRESSES = JSON.parse(
	fs.readFileSync(path.join(repoRoot, "e2e/devnet/addresses.json"), "utf8"),
) as { entryPoint: Address; sponsorshipPaymaster: Address };

const FACTORY_ABI = parseAbi([
	"function createEscrow(bytes32 salt) returns (address)",
	"function predictEscrowAddress(address payer, bytes32 salt) view returns (address)",
	"event EscrowCloneCreated(address indexed escrow, address indexed payer, bytes32 salt)",
]);
const ESCROW_ABI = parseAbi([
	"function confirm()",
	"function payer() view returns (address)",
	"function confirmed(address) view returns (bool)",
]);

const RPC = process.env.RPC_URL ?? ORIGINS.rpc;
const WALLET_API = process.env.WALLET_API_URL ?? ORIGINS.api;
const CHAIN_A = Number(process.env.CHAIN_ID ?? 31337);
/** anvil's account 7: no other spec sends from it, and the suite runs on one worker. */
const DEPLOYER = privateKeyToAccount(
	"0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
);

const client = createPublicClient({ transport: http(RPC) });
const tenant = TENANTS.stock;

async function deployFactory(): Promise<Address> {
	const wallet = createWalletClient({
		account: DEPLOYER,
		transport: http(RPC),
	});
	const hash = await wallet.deployContract({
		abi: FACTORY_ABI,
		bytecode: FACTORY.creationCode,
		chain: null,
	});
	const receipt = await client.waitForTransactionReceipt({ hash });
	if (!receipt.contractAddress)
		throw new Error("the factory deployment created no contract");
	return receipt.contractAddress;
}

// ── the tenant's sponsorship rules ────────────────────────────────────────────

type Rule = { id: string; contract: string };

async function rulesApi(
	method: "GET" | "POST" | "PATCH" | "DELETE",
	path: string,
	body?: unknown,
): Promise<unknown> {
	const separator = path.includes("?") ? "&" : "?";
	const response = await fetch(
		`${WALLET_API}/v1/admin/sponsorship/rules${path}${separator}chainId=${CHAIN_A}`,
		{
			method,
			headers: {
				authorization: `Bearer ${tenant.adminKey}`,
				...(body ? { "content-type": "application/json" } : {}),
			},
			body: body ? JSON.stringify(body) : undefined,
		},
	);
	const text = await response.text();
	expect(
		response.ok,
		`rules ${method} ${path} failed: ${response.status} ${text}`,
	).toBe(true);
	return text ? JSON.parse(text) : undefined;
}

/** Every rule this spec creates carries this prefix, so a run removes only its own. */
const RUN = `ps4-${Date.now()}`;
const created: string[] = [];

async function allow(
	contract: Address,
	options: {
		functions?: "all" | string[];
		reference: string;
		expiresAt?: Date;
	},
): Promise<Rule> {
	const rule = (await rulesApi("POST", "", {
		contract,
		functions: options.functions ?? "all",
		clientReference: `${RUN}-${options.reference}`,
		...(options.expiresAt
			? { expiresAt: options.expiresAt.toISOString() }
			: {}),
	})) as Rule;
	created.push(rule.id);
	return rule;
}

/** The ids of the rules that allowed each recent decision for this tenant. */
async function recentRuleIds(): Promise<string[][]> {
	const response = await fetch(
		`${WALLET_API}/v1/admin/sponsorship/decisions?chainId=${CHAIN_A}&outcome=allowed&limit=20`,
		{ headers: { authorization: `Bearer ${tenant.adminKey}` } },
	);
	const { decisions } = (await response.json()) as {
		decisions: Array<{ ruleIds: string[] }>;
	};
	return decisions.map((d) => d.ruleIds);
}

// ── sending a call from the dApp ──────────────────────────────────────────────

let sends = 0;

/**
 * Opens the wallet for one `eth_sendTransaction` from the dApp. The test dApp has a button for each
 * fixed call it makes; this adds one for the call given, so the popup opens on a real click. The
 * dApp logs the outcome under `label`.
 */
async function openSend(
	dapp: Page,
	credentials: VirtualCredential[],
	to: Address,
	data: Hex,
): Promise<{ popup: Page; label: string }> {
	sends += 1;
	const label = `send${sends}`;
	await dapp.evaluate(
		({ to, data, label }) => {
			type Giano = {
				provider: { request<T>(args: unknown): Promise<T> };
				log(label: string, value: unknown): void;
			};
			const { giano } = window as unknown as { giano: Giano };
			let button = document.getElementById("send-call");
			if (!button) {
				button = document.createElement("button");
				button.id = "send-call";
				button.textContent = "Send a call";
				document.body.append(button);
			}
			button.onclick = async () => {
				try {
					const hash = await giano.provider.request<string>({
						method: "eth_sendTransaction",
						params: [{ to, value: "0x0", data }],
					});
					giano.log(`${label}:userOpHash`, hash);
					const receipt = await giano.provider.request<{ success: boolean }>({
						method: "waitForUserOperationReceipt",
						params: [hash],
					});
					giano.log(`${label}:success`, receipt.success);
				} catch (error) {
					giano.log(`${label}:error`, (error as Error).message);
				}
			};
		},
		{ to, data, label },
	);
	const popup = await openActionPopup(dapp, "#send-call", credentials);
	return { popup, label };
}

/** Approves the call in the wallet and returns its user operation hash once it has landed. */
async function approveAndLand(
	dapp: Page,
	popup: Page,
	label: string,
): Promise<Hex> {
	await popup
		.getByRole("button", { name: tenant.ui.approveTx })
		.click({ timeout: 30_000 });
	const out = dapp.getByTestId("out");
	await expect(out).toContainText(`${label}:success: true`, {
		timeout: 90_000,
	});
	const text = (await out.textContent()) ?? "";
	const hash = text.match(
		new RegExp(`${label}:userOpHash: (0x[0-9a-fA-F]{64})`),
	)?.[1];
	if (!hash) throw new Error(`the dApp logged no operation hash for ${label}`);
	return hash as Hex;
}

/** The refusal the wallet shows before approval, with its reason. No approve button is offered. */
async function expectRefused(popup: Page, reason: string): Promise<void> {
	const refusal = popup.getByTestId("sponsorship-refusal");
	await refusal.waitFor({ state: "visible", timeout: 30_000 });
	await expect(refusal).toHaveAttribute("data-reason", reason);
	await expect(
		popup.getByRole("button", { name: tenant.ui.approveTx }),
	).toHaveCount(0);
	await popup.getByRole("button", { name: "Close" }).click();
}

/** True when Giano's paymaster paid for the operation, read from the EntryPoint's own event. */
async function sponsoredByPaymaster(
	sender: Address,
	userOpHash: Hex,
): Promise<boolean> {
	const logs = await client.getLogs({
		address: ADDRESSES.entryPoint,
		event: getAbiItem({ abi: entryPoint09Abi, name: "UserOperationEvent" }),
		args: { userOpHash, sender },
		fromBlock: 0n,
		toBlock: "latest",
		strict: true,
	});
	return (
		logs.length === 1 &&
		logs[0].args.paymaster.toLowerCase() ===
			ADDRESSES.sponsorshipPaymaster.toLowerCase() &&
		logs[0].args.success
	);
}

test.describe("sponsorship of contracts deployed at run time (PS-4)", () => {
	let factory: Address;
	let factoryRule: Rule;

	test.beforeAll(async () => {
		factory = await deployFactory();
		factoryRule = await allow(factory, { reference: "factory" });
	});

	test.afterAll(async () => {
		for (const id of created) {
			await fetch(
				`${WALLET_API}/v1/admin/sponsorship/rules/${id}?chainId=${CHAIN_A}`,
				{
					method: "DELETE",
					headers: { authorization: `Bearer ${tenant.adminKey}` },
				},
			);
		}
	});

	/** A fresh salt and the escrow address the connected wallet would deploy with it. */
	async function predictEscrow(wallet: Address) {
		const salt = keccak256(toHex(`${RUN}-${Math.random()}`));
		const escrow = await client.readContract({
			address: factory,
			abi: FACTORY_ABI,
			functionName: "predictEscrowAddress",
			args: [wallet, salt],
		});
		return { salt, escrow };
	}

	async function deployEscrow(
		page: Page,
		credentials: VirtualCredential[],
		wallet: Address,
		salt: Hex,
		escrow: Address,
	) {
		const deploy = await openSend(
			page,
			credentials,
			factory,
			encodeFunctionData({
				abi: FACTORY_ABI,
				functionName: "createEscrow",
				args: [salt],
			}),
		);
		const hash = await approveAndLand(page, deploy.popup, deploy.label);
		expect(await sponsoredByPaymaster(wallet, hash)).toBe(true);
		expect(
			await client.readContract({
				address: escrow,
				abi: ESCROW_ABI,
				functionName: "payer",
			}),
		).toBe(wallet);
	}

	const confirm = encodeFunctionData({
		abi: ESCROW_ABI,
		functionName: "confirm",
	});

	test("an allow-listed factory deploys an escrow under sponsorship, but a call to the escrow is refused until a rule names it", async ({
		page,
	}) => {
		const { credentials, address } = await connectWallet(page, tenant);
		const wallet = address as Address;
		const { salt, escrow } = await predictEscrow(wallet);

		await deployEscrow(page, credentials, wallet, salt, escrow);
		expect(
			(await recentRuleIds()).some((ids) => ids.includes(factoryRule.id)),
		).toBe(true);

		// No rule names the escrow, so the call is refused before the user is asked to approve.
		const refused = await openSend(page, credentials, escrow, confirm);
		await expectRefused(refused.popup, "contract-not-allowed");

		// One rule for the escrow, added without touching any other rule, and the call is sponsored.
		const rule = await allow(escrow, { reference: "late-escrow" });
		const allowed = await openSend(page, credentials, escrow, confirm);
		const hash = await approveAndLand(page, allowed.popup, allowed.label);
		expect(await sponsoredByPaymaster(wallet, hash)).toBe(true);
		expect((await recentRuleIds())[0]).toEqual([rule.id]);
	});

	test("a rule added for the predicted address before the deployment sponsors the first call, until it is removed or expires", async ({
		page,
	}) => {
		const { credentials, address } = await connectWallet(page, tenant);
		const wallet = address as Address;
		const { salt, escrow } = await predictEscrow(wallet);

		// The tenant's backend allows the escrow before it exists, as a retried request would.
		const body = {
			functions: ["confirm()"],
			reference: `escrow-${salt.slice(2, 10)}`,
			expiresAt: new Date(Date.now() + 10 * 60_000),
		};
		const rule = await allow(escrow, body);
		const retried = await allow(escrow, body);
		expect(retried.id).toBe(rule.id);

		await deployEscrow(page, credentials, wallet, salt, escrow);

		// The first call to the new escrow is sponsored with no further step, and the decision names
		// the rule that allowed it.
		const first = await openSend(page, credentials, escrow, confirm);
		const firstHash = await approveAndLand(page, first.popup, first.label);
		expect(await sponsoredByPaymaster(wallet, firstHash)).toBe(true);
		expect((await recentRuleIds())[0]).toEqual([rule.id]);
		expect(
			await client.readContract({
				address: escrow,
				abi: ESCROW_ABI,
				functionName: "confirmed",
				args: [wallet],
			}),
		).toBe(true);

		// An expired rule allows nothing.
		await rulesApi("PATCH", `/${rule.id}`, {
			expiresAt: new Date(Date.now() + 2_000).toISOString(),
		});
		await new Promise((resolve) => setTimeout(resolve, 2_500));
		const expired = await openSend(page, credentials, escrow, confirm);
		await expectRefused(expired.popup, "contract-not-allowed");

		// Neither does a removed one: renew the rule, then remove it.
		const renewed = await allow(escrow, {
			reference: `renewed-${salt.slice(2, 10)}`,
		});
		await rulesApi("DELETE", `/${renewed.id}`);
		const removed = await openSend(page, credentials, escrow, confirm);
		await expectRefused(removed.popup, "contract-not-allowed");
	});
});
