/**
 * The deployment plan: for every core contract, where its class says it should be (expected), where
 * this run will put or find it (actual), what code is there, and whether that is a deviation.
 *
 * The expected address is CREATE3(the chain's class deployer, the contract's label), or, for an
 * implementation the chain has been upgraded to, CREATE3 of its versioned label
 * (`giano.paymaster.impl@v2`, listed in the record's `upgrades`). The actual address is, in order:
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
	type LabelKey,
	type NetworkClass,
	type OverrideKey,
} from "./config";
import { create3Address } from "./create3";
import type { DeploymentRecord } from "./records";
import { DEV_RELEASE } from "./release";

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
	/** The base label, or the versioned one of a canonical upgrade target the record lists. */
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
	/**
	 * True when the deployment record already lists this contract at this address as a confirmed
	 * deviation (whatever reason a rerun now gives for it): an operator accepted it, so it is reported
	 * but not confirmed again.
	 */
	acknowledged: boolean;
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
	/**
	 * The release the run deploys. Existing code at a non-overridden address (deterministic or
	 * recorded) must be this release's; only an explicit override may hold any release.
	 */
	release?: string;
	/**
	 * A run that will deploy nothing (`deploy:cli core` without a key, e.g. the Helm Job): existing
	 * code may be any release's. A keyless `--plan` previews a deployment and keeps the check.
	 */
	verifyOnly?: boolean;
	/** For tests: the class deployer instead of deploy/config.ts. */
	deployer?: Address | null;
};

/** The code at `address`; when it is several releases' code, `release` (the run's) if one of them. */
async function codeAt(
	client: PublicClient,
	contract: ReleaseContractName,
	address: Address,
	release?: string,
): Promise<CodeState> {
	const code = await client.getCode({ address });
	if (!code || code === "0x") return { state: "empty" };
	const match = releaseOf(contract, code, address, release);
	return match
		? { state: "release", release: match.release }
		: { state: "foreign", codehash: keccak256(code) };
}

const same = (a: Address | null, b: Address | null) =>
	a !== null && b !== null && getAddress(a) === getAddress(b);

/**
 * The record's upgrade target for `key` at `address`, when it is the deterministic one: deployed by
 * `deployer` under its versioned label, so CREATE3(deployer, that label) is `address`. Such an
 * address is where every chain of the class has that upgrade, not a deviation.
 */
export function canonicalUpgrade(
	key: LabelKey,
	address: Address,
	deployer: Address | null,
	upgrades: DeploymentRecord["upgrades"] = [],
): DeploymentRecord["upgrades"][number] | undefined {
	if (!deployer) return undefined;
	return upgrades.find(
		(u) =>
			u.of === key &&
			same(u.address, address) &&
			same(create3Address(deployer, u.label), address),
	);
}

/**
 * Where `address`, recorded under `key`, sits for the class deployer: its expected address (the
 * versioned label's for a canonical upgrade target, else the base label's) and whether it is there.
 */
export function placementOf(
	key: LabelKey,
	address: Address,
	deployer: Address | null,
	upgrades: DeploymentRecord["upgrades"] = [],
): { expected: Address | null; deterministic: boolean } {
	const upgrade = canonicalUpgrade(key, address, deployer, upgrades);
	const expected = deployer
		? create3Address(deployer, upgrade?.label ?? LABELS[key])
		: null;
	return { expected, deterministic: same(address, expected) };
}

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
		const contract = CONTRACT_OF[key];
		const override = overrides[key] ? getAddress(overrides[key]) : null;
		const recorded = input.record?.contracts[key]?.address
			? getAddress(input.record.contracts[key].address)
			: null;
		// A recorded upgrade target at its own deterministic address (`upgrade --execute` records the
		// implementation the proxy now uses) is expected there; it may hold a newer release.
		const upgrade =
			recorded && !override
				? canonicalUpgrade(key, recorded, deployer, input.record?.upgrades)
				: undefined;
		const label = upgrade?.label ?? LABELS[key];
		const expected = deployer ? create3Address(deployer, label) : null;
		let actual: Address | null;
		let source: PlannedContract["source"];
		let code: CodeState = { state: "empty" };
		if (override) {
			actual = override;
			source = "override";
			code = await codeAt(client, contract, actual, input.release);
		} else if (recorded && (upgrade || !same(recorded, expected))) {
			actual = recorded;
			source = "recorded";
			code = await codeAt(client, contract, actual, input.release);
		} else {
			const atExpected = expected
				? await codeAt(client, contract, expected, input.release)
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
					: await codeAt(client, contract, actual, input.release);
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
		// A local `--release dev` run deploys unreleased code, which no fingerprint matches: on a rerun
		// that code is the run's own, not foreign (deployCore records it the same way). `dev` is no
		// published release either, so any release already on the local chain is accepted as is.
		const devCode = input.network === "local" && input.release === DEV_RELEASE;
		if (source === "override" || source === "recorded") {
			if (code.state === "empty")
				blockers.push(
					`${where} (${source}) has no code. An ${source === "override" ? "override" : "recorded address"} must already hold release code; it is never deployed.`,
				);
			else if (code.state === "foreign" && !devCode)
				blockers.push(
					`${where} (${source}) holds code ${code.codehash}, which matches no release's ${contract}.`,
				);
		} else if (code.state === "foreign" && !devCode)
			blockers.push(
				`${where} is occupied by code ${code.codehash} that matches no release's ${contract}. Stop and investigate; never overwrite the deployment record.`,
			);
		// A deployment mixes releases: it would deploy the missing contracts at the selected one next
		// to code of another. A verify-only run (the Helm Job) deploys nothing and accepts any release,
		// as deployCore does: a chain keeps the release it was adopted at.
		if (
			!input.verifyOnly &&
			source !== "override" &&
			!upgrade &&
			!devCode &&
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
			acknowledged: (input.record?.deviations ?? []).some(
				(d) => d.confirmed && d.contract === key && same(d.actual, actual),
			),
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
				`  - ${d.key}: expected ${d.expected ?? "(none)"}, actual ${d.actual ?? "(unknown)"} — ${DEVIATION_REASONS[d.reason]}${d.reason === "non-canonical-signer" ? ` (signer ${plan.signer}, canonical ${plan.classDeployer})` : ""}${d.acknowledged ? " (already confirmed in the deployment record)" : ""}`,
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

/** The deviations no operator has confirmed yet: those the record does not already list as confirmed. */
export function unacknowledged(plan: Plan): Deviation[] {
	return plan.deviations.filter((d) => !d.acknowledged);
}

/**
 * What a plan's deviations require before signing. Only mainnets gate, and only a run that signs: a
 * plan or verify-only run reports the deviations and goes on. A deviation the record already lists as
 * confirmed needs no new confirmation. Otherwise an interactive run must type `deviate <profile>`, and
 * a non-interactive one (`deploy:cli core` with a key) refuses. Nothing skips the typed confirmation.
 * Testnets and local chains only report.
 */
export function deviationGate(
	plan: Plan,
	profileId: string,
	options: { interactive: boolean; signs: boolean },
): DeviationGate {
	const pending = unacknowledged(plan);
	if (plan.network !== "mainnet" || pending.length === 0 || !options.signs)
		return { kind: "none" };
	if (!options.interactive)
		return {
			kind: "refuse",
			reason: `A non-interactive run refuses a mainnet deployment that deviates (${pending.map((d) => `${d.key}: ${d.reason}`).join("; ")}). Run the guided wizard (pnpm deploy:guided) to review and confirm it, or fix the deviation.`,
		};
	return { kind: "confirm", phrase: `deviate ${profileId}` };
}

/** Where an address in use on a chain sits relative to the class's deterministic addresses. */
export type Placement = {
	key: CoreKey;
	address: Address;
	/** CREATE3(class deployer, label); null when the class deployer is not configured. */
	expected: Address | null;
	deterministic: boolean;
};

/**
 * For each contract address in use, whether it is the deterministic one for `deployer`. An upgrade
 * target deployed under a versioned label (`giano.paymaster.impl@v2`, listed in the record's
 * `upgrades`) is deterministic too: its expected address is CREATE3 of that label, not the base one.
 */
export function placements(
	addresses: Partial<Record<CoreKey, Address>>,
	deployer: Address | null,
	upgrades: DeploymentRecord["upgrades"] = [],
): Placement[] {
	return CORE_KEYS.flatMap((key) => {
		const address = addresses[key];
		if (!address) return [];
		return [
			{
				key,
				address: getAddress(address),
				...placementOf(key, address, deployer, upgrades),
			},
		];
	});
}

/**
 * Non-deterministic addresses the chain's record does not list as a deviation. On a mainnet every
 * such address must have been confirmed by an operator when it was deployed or adopted, so with
 * `confirmedOnly` (doctor passes it for a mainnet profile) a deviation that was only reported does
 * not count; on a testnet a recorded one is enough.
 */
export function undeclaredDeviations(
	inUse: Placement[],
	record: DeploymentRecord | undefined,
	{ confirmedOnly = false }: { confirmedOnly?: boolean } = {},
): Placement[] {
	return inUse.filter(
		(p) =>
			p.expected !== null &&
			!p.deterministic &&
			!(record?.deviations ?? []).some(
				(d) =>
					d.contract === p.key &&
					same(d.actual, p.address) &&
					(!confirmedOnly || d.confirmed),
			),
	);
}

/**
 * Whether deploying an upgrade target under `label` with `signer` deviates. The target lands at
 * CREATE3(signer, label), so only the class's canonical deployer puts it where every chain of the
 * class has it. Another key is refused on a mainnet (like `deploy:cli core`, the CLI cannot take the
 * typed confirmation) and recorded as a deviation elsewhere, before anything is deployed.
 */
export function upgradeDeviation(
	network: NetworkClass,
	canonical: Address | null,
	signer: Address,
	key: "paymasterImplementation" | "walletImplementation",
	label: string,
):
	| { kind: "none" }
	| { kind: "refuse"; reason: string }
	| {
			kind: "record";
			message: string;
			deviation: Omit<Deviation, "acknowledged">;
	  } {
	if (!canonical || same(signer, canonical)) return { kind: "none" };
	const deviation = {
		key,
		reason: "non-canonical-signer" as const,
		expected: create3Address(canonical, label),
		actual: create3Address(signer, label),
	};
	const message = `${label} would be deployed by ${signer}, not the ${network} canonical deployer ${canonical}: at ${deviation.actual} instead of ${deviation.expected}`;
	if (network === "mainnet")
		return {
			kind: "refuse",
			reason: `refusing to upgrade: ${message}. Load the mainnet canonical deployer key from its 1Password item into DEPLOYER_PRIVATE_KEY.`,
		};
	return { kind: "record", message, deviation };
}
