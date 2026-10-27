/** Read-only gates shared by the interactive testnet deployer and its regression tests. */
import {
	type Address,
	getAddress,
	keccak256,
	type PublicClient,
	parseEther,
	zeroAddress,
} from "viem";
import { CANONICAL_CODE } from "../canonical";
import { gianoPaymasterAbi, gianoSmartWalletFactoryAbi } from "../generated";
import {
	CANONICAL_DEPLOYER,
	DEPLOYER_IS_PLACEHOLDER,
	ENTRY_POINT_V07,
	LABELS,
} from "./config";
import { CREATEX_ADDRESS, create3Address } from "./create3";

export const TESTNETS = {
	"base-sepolia": {
		id: 84532,
		name: "Base Sepolia",
		rpc: "https://sepolia.base.org",
	},
	"ethereum-sepolia": {
		id: 11155111,
		name: "Ethereum Sepolia",
		rpc: "https://ethereum-sepolia-rpc.publicnode.com",
	},
} as const;
export type Network = keyof typeof TESTNETS;
export const CORE_KEYS = [
	"walletImplementation",
	"factory",
	"paymasterImplementation",
	"paymasterProxy",
] as const;
export const PAYMASTER_DEFAULTS = {
	defaultFeeWei: 100_000_000_000_000n,
	postOpGasAllowance: 40000,
	penaltyBps: 1000,
};
export const MIN_DEPLOYER_BALANCE = parseEther("0.05");
// Same reference as giano-doctor: includes the canonical SenderCreator immutable.
export const ENTRY_POINT_CODEHASH =
	"0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58";
// CreateX upstream README, Security Considerations (pinned runtime hash).
export const CREATEX_CODEHASH =
	"0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f";
export const IMPLEMENTATION_SLOT =
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

export function networkFor(value: string): Network {
	if (!(value in TESTNETS) || !Object.hasOwn(TESTNETS, value))
		throw new Error(
			"Choose base-sepolia or ethereum-sepolia (only supported targets).",
		);
	return value as Network;
}

export function roleAdmin(value: string): Address {
	const address = getAddress(value);
	if (address === zeroAddress)
		throw new Error("ROLE_ADMIN must be a nonzero address.");
	return address;
}

export function expectedCodehash(
	key: (typeof CORE_KEYS)[number],
	release: string,
): string {
	const address = create3Address(CANONICAL_DEPLOYER, LABELS[key]);
	const entry = CANONICAL_CODE[address]?.find(
		(entry) => entry.label === LABELS[key] && entry.release === release,
	);
	if (!entry)
		throw new Error(
			`Regenerate canonical.ts for ${release} and the selected canonical deployer: pnpm -F @appliedblockchain/giano-contracts gen:canonical`,
		);
	return entry.codehash;
}

/** Existing proxies need storage checks too: their runtime hash does not identify the implementation. */
export async function verifyCoreState(
	client: PublicClient,
	admin: Address,
): Promise<void> {
	const factory = create3Address(CANONICAL_DEPLOYER, LABELS.factory);
	const proxy = create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
	const factoryCode = await client.getCode({ address: factory });
	if (factoryCode && factoryCode !== "0x") {
		const implementation = await client.readContract({
			address: factory,
			abi: gianoSmartWalletFactoryAbi,
			functionName: "implementation",
		});
		if (
			getAddress(implementation) !==
			create3Address(CANONICAL_DEPLOYER, LABELS.walletImplementation)
		)
			throw new Error("Factory points to a different wallet implementation.");
	}
	const code = await client.getCode({ address: proxy });
	if (!code || code === "0x") return;
	const slot = await client.getStorageAt({
		address: proxy,
		slot: IMPLEMENTATION_SLOT,
	});
	if (
		!slot ||
		getAddress(`0x${slot.slice(-40)}`) !==
			create3Address(CANONICAL_DEPLOYER, LABELS.paymasterImplementation)
	)
		throw new Error(
			"Paymaster was upgraded or points to an unexpected implementation; use the upgrade procedure.",
		);
	const read = { address: proxy, abi: gianoPaymasterAbi } as const;
	const role = await client.readContract({
		...read,
		functionName: "ROLE_ADMIN",
	});
	const [allowed, entryPoint, fee, allowance, penalty] = await Promise.all([
		client.readContract({
			...read,
			functionName: "hasRole",
			args: [role, admin],
		}),
		client.readContract({ ...read, functionName: "entryPoint" }),
		client.readContract({ ...read, functionName: "defaultFeeWei" }),
		client.readContract({ ...read, functionName: "postOpGasAllowance" }),
		client.readContract({ ...read, functionName: "penaltyBps" }),
	]);
	if (
		!allowed ||
		getAddress(entryPoint) !== getAddress(ENTRY_POINT_V07) ||
		fee !== PAYMASTER_DEFAULTS.defaultFeeWei ||
		allowance !== PAYMASTER_DEFAULTS.postOpGasAllowance ||
		penalty !== PAYMASTER_DEFAULTS.penaltyBps
	)
		throw new Error(
			"Existing paymaster admin, EntryPoint or fee parameters differ from this plan. Review its configuration before continuing.",
		);
}

export type Check = { ok: boolean; message: string };
export async function inspectTestnet(
	client: PublicClient,
	network: Network,
	release: string,
	admin: Address,
): Promise<Check[]> {
	const checks: Check[] = [];
	async function check(message: string, action: () => Promise<unknown>) {
		try {
			const detail = await action();
			checks.push({
				ok: true,
				message: typeof detail === "string" ? `${message}: ${detail}` : message,
			});
		} catch (error) {
			// RPC errors can contain credential-bearing URLs. Only expose our own actionable messages.
			checks.push({
				ok: false,
				message: `${message}: ${error instanceof GateError ? error.message : "RPC/read failed; check endpoint access and retry (provider details suppressed)."}`,
			});
		}
	}
	await check(
		`RPC is ${TESTNETS[network].name} (${TESTNETS[network].id})`,
		async () => {
			if ((await client.getChainId()) !== TESTNETS[network].id)
				throw new GateError(
					"Wrong chain: provide the selected network's RPC URL. No transactions sent.",
				);
		},
	);
	if (!checks[0].ok) return checks;
	await check(`CreateX exists at ${CREATEX_ADDRESS}`, async () => {
		const code = await client.getCode({ address: CREATEX_ADDRESS });
		if (!code || keccak256(code) !== CREATEX_CODEHASH)
			throw new GateError(
				"Missing or unrecognised CreateX runtime. Follow https://github.com/pcaversaccio/createx; do not install local-chain substitutes.",
			);
	});
	await check("Canonical EntryPoint v0.7 runtime", async () => {
		const code = await client.getCode({ address: ENTRY_POINT_V07 });
		if (!code || keccak256(code) !== ENTRY_POINT_CODEHASH)
			throw new GateError(
				"Missing or noncanonical EntryPoint. Do not deploy or serve this chain.",
			);
	});
	let missing = false;
	for (const key of CORE_KEYS) {
		await check(
			`${key} at ${create3Address(CANONICAL_DEPLOYER, LABELS[key])}`,
			async () => {
				let expected: string;
				try {
					expected = expectedCodehash(key, release);
				} catch {
					throw new GateError(
						"Canonical release data is stale. Run gen:canonical and commit the regenerated output.",
					);
				}
				const code = await client.getCode({
					address: create3Address(CANONICAL_DEPLOYER, LABELS[key]),
				});
				if (!code || code === "0x") {
					missing = true;
					return "empty; will deploy";
				}
				if (keccak256(code) !== expected)
					throw new GateError(
						"Occupied by code other than the selected release. Stop and investigate; never overwrite the deployment record.",
					);
				return "already deployed; selected release verified";
			},
		);
	}
	await check(
		"Existing factory/paymaster configuration matches the plan (when present)",
		async () => {
			try {
				await verifyCoreState(client, admin);
			} catch {
				throw new GateError(
					"Configuration could not be verified or differs from this plan. Review factory implementation, proxy implementation slot, ROLE_ADMIN, EntryPoint and fee parameters.",
				);
			}
		},
	);
	if (missing && !DEPLOYER_IS_PLACEHOLDER)
		await check(
			`Canonical deployer has at least 0.05 test ETH (conservative gas reserve)`,
			async () => {
				if (
					(await client.getBalance({ address: CANONICAL_DEPLOYER })) <
					MIN_DEPLOYER_BALANCE
				)
					throw new GateError(
						`Fund ${CANONICAL_DEPLOYER} on ${TESTNETS[network].name}, then rerun. Reserve is not a gas quote; Base L1 data fees and changing gas prices need headroom.`,
					);
			},
		);
	return checks;
}
class GateError extends Error {}
