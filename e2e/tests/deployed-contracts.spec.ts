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

// ── the tenant's sponsorship configuration ────────────────────────────────────

type AllowlistEntry = { contract: string; functions: "all" | string[] };

async function adminCall(
	method: "GET" | "PUT",
	body?: unknown,
): Promise<Record<string, unknown>> {
	const response = await fetch(
		`${WALLET_API}/v1/admin/sponsorship?chainId=${CHAIN_A}`,
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
		`sponsorship ${method} failed: ${response.status} ${text}`,
	).toBe(true);
	return method === "GET"
		? (JSON.parse(text) as { config: Record<string, unknown> }).config
		: {};
}

/** Adds `contracts` to the tenant's allowlist, with every function allowed. */
async function allowContracts(
	original: Record<string, unknown>,
	contracts: Address[],
): Promise<void> {
	const allowlist = original.allowlist as AllowlistEntry[];
	await adminCall("PUT", {
		...original,
		allowlist: [
			...allowlist,
			...contracts.map((contract) => ({
				contract: contract.toLowerCase(),
				functions: "all",
			})),
		],
	});
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
	let original: Record<string, unknown>;

	test.beforeAll(async () => {
		factory = await deployFactory();
		original = await adminCall("GET");
	});

	test.afterEach(async () => {
		await adminCall("PUT", original);
	});

	test("an allow-listed factory deploys an escrow under sponsorship, but a call to the escrow is refused until its address is allowed", async ({
		page,
	}) => {
		await allowContracts(original, [factory]);
		const { credentials, address } = await connectWallet(page, tenant);
		const wallet = address as Address;

		// The escrow's address is known before it exists.
		const salt = keccak256(toHex(`escrow-${Date.now()}`));
		const escrow = await client.readContract({
			address: factory,
			abi: FACTORY_ABI,
			functionName: "predictEscrowAddress",
			args: [wallet, salt],
		});

		// 1. The deployment: a call to the factory, which the allowlist names.
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
		const deployHash = await approveAndLand(page, deploy.popup, deploy.label);
		expect(await sponsoredByPaymaster(wallet, deployHash)).toBe(true);
		const [created] = await client.getContractEvents({
			address: factory,
			abi: FACTORY_ABI,
			eventName: "EscrowCloneCreated",
			args: { payer: wallet },
			fromBlock: 0n,
			strict: true,
		});
		expect(created.args.escrow).toBe(escrow);
		expect(
			await client.readContract({
				address: escrow,
				abi: ESCROW_ABI,
				functionName: "payer",
			}),
		).toBe(wallet);

		// 2. A call to the new escrow: no rule names it, so it is refused before the user is asked
		//    to approve.
		const confirm = encodeFunctionData({
			abi: ESCROW_ABI,
			functionName: "confirm",
		});
		const refused = await openSend(page, credentials, escrow, confirm);
		await expectRefused(refused.popup, "contract-not-allowed");

		// 3. Once the tenant allows the escrow's address, the same call is sponsored.
		await allowContracts(original, [factory, escrow]);
		const allowed = await openSend(page, credentials, escrow, confirm);
		const confirmHash = await approveAndLand(
			page,
			allowed.popup,
			allowed.label,
		);
		expect(await sponsoredByPaymaster(wallet, confirmHash)).toBe(true);
		expect(
			await client.readContract({
				address: escrow,
				abi: ESCROW_ABI,
				functionName: "confirmed",
				args: [wallet],
			}),
		).toBe(true);
	});
});
