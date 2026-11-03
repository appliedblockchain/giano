/** Read-only gates shared by the guided deployer, the operator workflows and their regression tests. */
import {
	type Address,
	getAddress,
	keccak256,
	type PublicClient,
	parseEther,
	zeroAddress,
} from "viem";
import { isCanonicalEntryPointCode } from "../entrypoint";
import { gianoPaymasterAbi } from "../generated";
import { ENTRY_POINT_V09 } from "./config";
import { CREATEX_ADDRESS } from "./create3";
import {
	CORE_KEYS,
	formatPlan,
	IMPLEMENTATION_SLOT,
	type Plan,
	planCore,
} from "./plan";
import { type ChainProfile, paymasterParams } from "./profiles";
import type { DeploymentRecord } from "./records";

export { CORE_KEYS, IMPLEMENTATION_SLOT };

// CreateX upstream README, Security Considerations (pinned runtime hash).
export const CREATEX_CODEHASH =
	"0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f";

export function roleAdmin(value: string): Address {
	const address = getAddress(value);
	if (address === zeroAddress)
		throw new Error("ROLE_ADMIN must be a nonzero address.");
	return address;
}

const planned = (plan: Plan, key: (typeof CORE_KEYS)[number]) =>
	plan.contracts.find((c) => c.key === key);

/**
 * An existing paymaster proxy must be configured as this plan says: initialised with the planned
 * implementation (unless the proxy itself is an override, which the plan checked holds paymaster
 * code), with ROLE_ADMIN, EntryPoint and fees as the profile publishes them.
 */
export async function verifyCoreState(
	client: PublicClient,
	admin: Address,
	profile: ChainProfile,
	plan: Plan,
): Promise<void> {
	const proxy = planned(plan, "paymasterProxy");
	if (!proxy?.actual) return;
	const code = await client.getCode({ address: proxy.actual });
	if (!code || code === "0x") return;
	const implementation = planned(plan, "paymasterImplementation")?.actual;
	if (proxy.source !== "override") {
		const slot = await client.getStorageAt({
			address: proxy.actual,
			slot: IMPLEMENTATION_SLOT,
		});
		if (
			!slot ||
			!implementation ||
			getAddress(`0x${slot.slice(-40)}`) !== getAddress(implementation)
		)
			throw new Error(
				"Paymaster was upgraded or points to an unexpected implementation; use the upgrade procedure.",
			);
	}
	const read = { address: proxy.actual, abi: gianoPaymasterAbi } as const;
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
		getAddress(entryPoint) !== getAddress(ENTRY_POINT_V09) ||
		fee !== paymasterParams(profile).defaultFeeWei ||
		allowance !== profile.paymaster.postOpGasAllowance ||
		penalty !== profile.paymaster.penaltyBps
	)
		throw new Error(
			"Existing paymaster admin, EntryPoint or fee parameters differ from this plan. Review its configuration before continuing.",
		);
}

export type Check = { ok: boolean; message: string };

export type InspectOptions = {
	/** The signing key's address; null for a plan without a key. */
	signer: Address | null;
	record?: DeploymentRecord;
	/** For tests: the class deployer instead of deploy/config.ts. */
	deployer?: Address | null;
};

export type Inspection = {
	checks: Check[];
	/** Absent when the RPC is not the profile's chain (nothing else is read then). */
	plan?: Plan;
};

/**
 * Every read-only check before a deployment: the chain, CreateX, the EntryPoint, the plan (expected
 * and actual address per contract, overrides verified, deviations classified) and the existing
 * configuration. Signing is safe only when every check is ok; deviations are the caller's gate.
 */
export async function inspectDeployment(
	client: PublicClient,
	profile: ChainProfile,
	release: string,
	admin: Address,
	options: InspectOptions,
): Promise<Inspection> {
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
	await check(`RPC is ${profile.name} (${profile.chainId})`, async () => {
		if ((await client.getChainId()) !== profile.chainId)
			throw new GateError(
				"Wrong chain: provide the selected network's RPC URL. No transactions sent.",
			);
	});
	if (!checks[0].ok) return { checks };
	await check(`CreateX exists at ${CREATEX_ADDRESS}`, async () => {
		const code = await client.getCode({ address: CREATEX_ADDRESS });
		if (!code || keccak256(code) !== CREATEX_CODEHASH)
			throw new GateError(
				"Missing or unrecognised CreateX runtime. Follow https://github.com/pcaversaccio/createx; do not install local-chain substitutes.",
			);
	});
	await check("Canonical EntryPoint v0.9 runtime", async () => {
		const code = await client.getCode({ address: ENTRY_POINT_V09 });
		if (!isCanonicalEntryPointCode(code, profile.chainId))
			throw new GateError(
				"Missing or noncanonical EntryPoint. Do not deploy or serve this chain.",
			);
	});
	let plan: Plan | undefined;
	await check(`Deployment plan (${profile.network})`, async () => {
		try {
			plan = await planCore(client, {
				network: profile.network,
				signer: options.signer,
				overrides: profile.addresses,
				record: options.record,
				release,
				deployer: options.deployer,
			});
		} catch {
			throw new GateError(
				"Could not read the planned addresses; check endpoint access and retry.",
			);
		}
		return `\n${formatPlan(plan).join("\n")}`;
	});
	if (!plan) return { checks };
	for (const blocker of plan.blockers)
		checks.push({ ok: false, message: blocker });
	await check(
		"Existing paymaster configuration matches the plan (when present)",
		async () => {
			try {
				await verifyCoreState(client, admin, profile, plan as Plan);
			} catch {
				throw new GateError(
					"Configuration could not be verified or differs from this plan. Review the proxy implementation slot, ROLE_ADMIN, EntryPoint and fee parameters.",
				);
			}
		},
	);
	const signer = plan.signer;
	const missing = plan.contracts.some(
		(c) => c.code.state === "empty" && c.source !== "override",
	);
	if (missing && signer)
		await check(
			`Signer ${signer} has at least ${profile.minDeployerBalanceEth} ETH (conservative gas reserve)`,
			async () => {
				if (
					(await client.getBalance({ address: signer })) <
					parseEther(profile.minDeployerBalanceEth)
				)
					throw new GateError(
						`Fund ${signer} on ${profile.name}, then rerun. Reserve is not a gas quote; L1 data fees and changing gas prices need headroom.`,
					);
			},
		);
	return { checks, plan };
}
class GateError extends Error {}
