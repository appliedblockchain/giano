/**
 * The deployment plan: for every core contract, where its class says it should be (expected), where
 * this run will put or find it (actual), what code is there, and whether that is a deviation.
 *
 * The expected address is CREATE3(the chain's class deployer, the contract's label). The actual
 * address is, in order:
 *   1. the profile's override (`addresses` in deploy/chains/<profile>.json);
 *   2. the address the chain's deployment record already lists, when that is not the expected one;
 *   3. the expected address, when a contract is already there;
 *   4. CREATE3(the signing key's address, the label): CreateX's permissioned salt binds the address
 *      to the sender, so a key other than the class deployer can never land on the expected address.
 *
 * Nothing here signs or sends. The guided wizard and `deploy:cli core` both build this plan, print it,
 * gate on its deviations (mainnet) and then hand the actual addresses to deployCore.
 */
import {
	type Address,
	getAddress,
	type Hex,
	keccak256,
	type PublicClient,
} from "viem";
import { gianoSmartWalletFactoryAbi } from "../generated";
import { type ReleaseContractName, releaseOf } from "../release-code";
import {
	CONTRACT_OF,
	classDeployer,
	LABELS,
	type NetworkClass,
	type OverrideKey,
} from "./config";
import { create3Address } from "./create3";
import type { DeploymentRecord } from "./records";

export const CORE_KEYS = [
	"walletImplementation",
	"factory",
	"paymasterImplementation",
	"paymasterProxy",
] as const;
export type CoreKey = (typeof CORE_KEYS)[number];

/** ERC-1967 implementation slot. */
export const IMPLEMENTATION_SLOT =
	"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

export type DeviationReason =
	/** The profile overrides the contract's address. */
	| "override"
	/** The signing key is not the class's canonical deployer, so it deploys at its own addresses. */
	| "non-canonical-signer"
	/** The chain already has the contract, at an address other than the expected one. */
	| "existing-elsewhere";

export const DEVIATION_REASONS: Record<DeviationReason, string> = {
	override: "address overridden in the chain profile",
	"non-canonical-signer":
		"signed by a key that is not the class's canonical deployer",
	"existing-elsewhere":
		"already deployed at a non-deterministic address (deployment record)",
};

export type CodeState =
	| { state: "empty" }
	| { state: "release"; release: string }
	| { state: "foreign"; codehash: Hex };

export type PlannedContract = {
	key: CoreKey;
	label: string;
	contract: ReleaseContractName;
	/** CREATE3(class deployer, label); null when the class's deployer is not configured, or for the timelock. */
	expected: Address | null;
	/** Where this run finds or deploys it; null when neither a key nor the class deployer is known. */
	actual: Address | null;
	source: "override" | "recorded" | "deterministic" | "signer" | "unknown";
	code: CodeState;
	deviation?: DeviationReason;
};

export type Deviation = {
	key: CoreKey;
	reason: DeviationReason;
	expected: Address | null;
	actual: Address | null;
};

export type Plan = {
	network: NetworkClass;
	/** The class's canonical deployer; null when not configured yet (the run must not sign). */
	classDeployer: Address | null;
	/** The address of the signing key; null for a run without a key (plan or verify only). */
	signer: Address | null;
	contracts: PlannedContract[];
	deviations: Deviation[];
	/** Reasons this plan must not be executed, whatever the operator confirms. */
	blockers: string[];
};

export type PlanInput = {
	network: NetworkClass;
	signer: Address | null;
	overrides?: Partial<Record<OverrideKey, string>>;
	record?: DeploymentRecord;
	/** The release the run deploys. Existing code at a non-overridden address must be this release's. */
	release?: string;
	/** For tests: the class deployer instead of deploy/config.ts. */
	deployer?: Address | null;
};

async function codeAt(
	client: PublicClient,
	contract: ReleaseContractName,
	address: Address,
): Promise<CodeState> {
	const code = await client.getCode({ address });
	if (!code || code === "0x") return { state: "empty" };
	const match = releaseOf(contract, code, address);
	return match
		? { state: "release", release: match.release }
		: { state: "foreign", codehash: keccak256(code) };
}

const same = (a: Address | null, b: Address | null) =>
	a !== null && b !== null && getAddress(a) === getAddress(b);

/** Builds the plan from the chain's state. Reads only. */
export async function planCore(
	client: PublicClient,
	input: PlanInput,
): Promise<Plan> {
	const deployer =
		input.deployer === undefined
			? classDeployer(input.network)
			: input.deployer;
	const signer = input.signer ? getAddress(input.signer) : null;
	const overrides = input.overrides ?? {};
	const blockers: string[] = [];
	if (!deployer)
		blockers.push(
			`The ${input.network} canonical deployer is not configured (DEPLOYERS.${input.network} in packages/contracts/deploy/config.ts). Nothing can be signed for a ${input.network} chain until it is set.`,
		);

	const contracts: PlannedContract[] = [];
	for (const key of CORE_KEYS) {
		const label = LABELS[key];
		const contract = CONTRACT_OF[key];
		const expected = deployer ? create3Address(deployer, label) : null;
		const override = overrides[key] ? getAddress(overrides[key]) : null;
		const recorded = input.record?.contracts[key]?.address
			? getAddress(input.record.contracts[key].address)
			: null;
		let actual: Address | null;
		let source: PlannedContract["source"];
		let code: CodeState = { state: "empty" };
		if (override) {
			actual = override;
			source = "override";
			code = await codeAt(client, contract, actual);
		} else if (recorded && !same(recorded, expected)) {
			actual = recorded;
			source = "recorded";
			code = await codeAt(client, contract, actual);
		} else {
			const atExpected = expected
				? await codeAt(client, contract, expected)
				: undefined;
			if (expected && atExpected && atExpected.state !== "empty") {
				actual = expected;
				source = "deterministic";
				code = atExpected;
			} else if (signer) {
				actual = create3Address(signer, label);
				source = same(actual, expected) ? "deterministic" : "signer";
				code = same(actual, expected)
					? (atExpected ?? { state: "empty" })
					: await codeAt(client, contract, actual);
			} else {
				actual = expected;
				source = expected ? "deterministic" : "unknown";
				code = atExpected ?? { state: "empty" };
			}
		}
		let deviation: DeviationReason | undefined;
		if (expected && !same(actual, expected))
			deviation =
				source === "override"
					? "override"
					: source === "recorded"
						? "existing-elsewhere"
						: "non-canonical-signer";
		contracts.push({
			key,
			label,
			contract,
			expected,
			actual,
			source,
			code,
			deviation,
		});

		const where = `${key} at ${actual}`;
		if (source === "override" || source === "recorded") {
			if (code.state === "empty")
				blockers.push(
					`${where} (${source}) has no code. An ${source === "override" ? "override" : "recorded address"} must already hold release code; it is never deployed.`,
				);
			else if (code.state === "foreign")
				blockers.push(
					`${where} (${source}) holds code ${code.codehash}, which matches no release's ${contract}.`,
				);
		} else if (code.state === "foreign")
			blockers.push(
				`${where} is occupied by code ${code.codehash} that matches no release's ${contract}. Stop and investigate; never overwrite the deployment record.`,
			);
		else if (
			code.state === "release" &&
			input.release &&
			code.release !== input.release
		)
			blockers.push(
				`${where} already holds release ${code.release}, not the selected ${input.release}. Select ${code.release}, or use the upgrade procedure.`,
			);
	}

	blockers.push(...(await immutableProblems(client, contracts)));

	const deviations = contracts
		.filter((c) => c.deviation)
		.map(({ key, deviation, expected, actual }) => ({
			key,
			reason: deviation as DeviationReason,
			expected,
			actual,
		}));
	return {
		network: input.network,
		classDeployer: deployer,
		signer,
		contracts,
		deviations,
		blockers,
	};
}

/**
 * The semantic checks behind the masked immutables (deploy/immutable-checks.ts), for contracts that
 * already exist, overrides included: an existing factory must clone the planned wallet
 * implementation, and an existing paymaster proxy (itself release proxy code, which codeAt checked)
 * must point at the planned paymaster implementation, which must be paymaster release code.
 */
async function immutableProblems(
	client: PublicClient,
	contracts: PlannedContract[],
): Promise<string[]> {
	const problems: string[] = [];
	const find = (key: CoreKey) => contracts.find((c) => c.key === key);
	const factory = find("factory");
	const wallet = find("walletImplementation");
	if (factory?.actual && factory.code.state === "release") {
		const implementation = (await client.readContract({
			address: factory.actual,
			abi: gianoSmartWalletFactoryAbi,
			functionName: "implementation",
		})) as Address;
		if (!same(implementation, wallet?.actual ?? null))
			problems.push(
				`factory at ${factory.actual} clones the wallet implementation ${implementation}, not the planned ${wallet?.actual}. Override walletImplementation with ${implementation}, or investigate.`,
			);
	}
	const proxy = find("paymasterProxy");
	const paymaster = find("paymasterImplementation");
	if (proxy?.actual && proxy.code.state === "release") {
		const slot = await client.getStorageAt({
			address: proxy.actual,
			slot: IMPLEMENTATION_SLOT,
		});
		const implementation = slot ? getAddress(`0x${slot.slice(-40)}`) : null;
		const code = implementation
			? await codeAt(client, "GianoPaymaster", implementation)
			: ({ state: "empty" } as const);
		if (code.state !== "release")
			problems.push(
				`paymaster proxy at ${proxy.actual} points at ${implementation ?? "nothing"}, which holds no paymaster release code.`,
			);
		else if (!same(implementation, paymaster?.actual ?? null))
			problems.push(
				`paymaster proxy at ${proxy.actual} points at ${implementation}, not the planned paymaster implementation ${paymaster?.actual}. Override paymasterImplementation with ${implementation}, or use the upgrade procedure.`,
			);
	}
	return problems;
}

/**
 * The addresses deployCore must use rather than derive from the signer: overrides, recorded
 * addresses, and anything already deployed (a non-canonical signer reuses a contract already at the
 * expected address instead of deploying its own).
 */
export function fixedAddresses(plan: Plan): Partial<Record<CoreKey, Address>> {
	const fixed: Partial<Record<CoreKey, Address>> = {};
	for (const c of plan.contracts) {
		if (!c.actual) continue;
		if (
			c.code.state !== "empty" ||
			c.source === "override" ||
			c.source === "recorded"
		)
			fixed[c.key] = c.actual;
	}
	return fixed;
}

function describeCode(code: CodeState): string {
	return code.state === "empty"
		? "empty; will deploy"
		: code.state === "release"
			? `release ${code.release}`
			: `FOREIGN code ${code.codehash}`;
}

/** One line per contract: expected, actual, code and deviation. */
export function formatPlan(plan: Plan): string[] {
	const lines = [
		`Network class: ${plan.network}; canonical deployer: ${plan.classDeployer ?? "NOT CONFIGURED"}; signer: ${plan.signer ?? "none (plan/verify only)"}`,
	];
	for (const c of plan.contracts) {
		const deviation = c.deviation
			? `  DEVIATION: ${DEVIATION_REASONS[c.deviation]}`
			: "";
		lines.push(
			`  ${c.key.padEnd(24)} expected ${c.expected ?? "(none)"}  actual ${c.actual ?? "(unknown)"}  [${c.actual ? describeCode(c.code) : "not checked: no deployer or key to derive the address from"}]${deviation}`,
		);
	}
	return lines;
}

/** The mainnet deviation warning: each deviation, and what it means for the chain. */
export function deviationWarning(plan: Plan, chainName: string): string[] {
	return [
		"",
		"!".repeat(78),
		`WARNING: this ${plan.network} deployment on ${chainName} deviates from the deterministic addresses.`,
		...plan.deviations.map(
			(d) =>
				`  - ${d.key}: expected ${d.expected ?? "(none)"}, actual ${d.actual ?? "(unknown)"} — ${DEVIATION_REASONS[d.reason]}${d.reason === "non-canonical-signer" ? ` (signer ${plan.signer}, canonical ${plan.classDeployer})` : ""}`,
		),
		`Contract addresses on ${chainName} will differ from the other ${plan.network} chains, permanently.`,
		"The deployment record keeps every deviation, and giano-doctor reports it.",
		"!".repeat(78),
	];
}

export type DeviationGate =
	/** Nothing to confirm beyond the usual deployment confirmation. */
	| { kind: "none" }
	/** The operator must type `phrase` before anything is signed. */
	| { kind: "confirm"; phrase: string }
	/** The run must not sign: a mainnet deviation with no way to confirm it. */
	| { kind: "refuse"; reason: string };

/**
 * What a plan's deviations require before signing. Only mainnets gate: an interactive run must type
 * `deviate <profile>`, and a non-interactive one (`deploy:cli core`) always refuses. Nothing skips the
 * typed confirmation. Testnets and local chains only report.
 */
export function deviationGate(
	plan: Plan,
	profileId: string,
	options: { interactive: boolean },
): DeviationGate {
	if (plan.network !== "mainnet" || plan.deviations.length === 0)
		return { kind: "none" };
	if (!options.interactive)
		return {
			kind: "refuse",
			reason: `A non-interactive run refuses a mainnet deployment that deviates (${plan.deviations.map((d) => `${d.key}: ${d.reason}`).join("; ")}). Run the guided wizard (pnpm deploy:guided) to review and confirm it, or fix the deviation.`,
		};
	return { kind: "confirm", phrase: `deviate ${profileId}` };
}
