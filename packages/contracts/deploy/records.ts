/**
 * deployments/<chainId>.json: what is deployed where, written by the deploy CLI and committed for
 * every chain except the local ones. scripts/generate-addresses.ts builds addresses.ts from these.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import type { Address, Hex } from "viem";
import type { LabelKey, NetworkClass } from "./config";
import type { DeviationReason } from "./plan";

export const DEPLOYMENTS_DIR = path.resolve(
	import.meta.dirname,
	"..",
	"deployments",
);

export type DeployedContract = {
	address: Address;
	label: string;
	release: string;
	/** keccak256 of the runtime code found at `address` after the deployment. */
	codehash: Hex;
	/**
	 * The release fingerprint the code matched (release-fingerprints.ts): the code hash with the
	 * immutables masked. Absent only for `dev` builds on local chains, which match no release.
	 */
	fingerprint?: Hex;
	/** CREATE3(the class deployer, label); null when the class deployer was not configured. */
	expected?: Address | null;
	/** True when `address` is `expected`: the contract sits where every chain of the class has it. */
	deterministic?: boolean;
	/** Absent when the contract was already there when the CLI ran. */
	transactionHash?: Hex;
};

/** A deviation from the deterministic addresses, as the run reported it and the operator confirmed it. */
export type RecordedDeviation = {
	contract: string;
	reason: DeviationReason;
	expected: Address | null;
	actual: Address | null;
	/** ISO timestamp of the run that recorded it. */
	at: string;
	/** True when the operator typed the deviation phrase (mainnet), false when it was only reported (testnet). */
	confirmed: boolean;
};

export type DeploymentRecord = {
	chainId: number;
	/** The chain's network class, which selects the canonical deployer and the expected addresses. */
	network?: NetworkClass;
	/** The address that signed the deployments: the class's canonical deployer unless a deviation says otherwise. */
	deployer: Address;
	contracts: Partial<Record<LabelKey, DeployedContract>>;
	/** Upgrade targets deployed under versioned labels (`giano.paymaster.impl@v2`), oldest first. */
	upgrades: (DeployedContract & { of: LabelKey })[];
	/**
	 * The paymaster's GianoTimelock (G9). Not canonical: plain CREATE, operator-specific
	 * proposers and delays. `delays` is the policy it was deployed with, in seconds.
	 */
	timelock?: DeployedContract & {
		proposers: Address[];
		executors: Address[];
		delays: Record<string, number>;
	};
	/** Every deviation from the deterministic addresses, oldest first. Never removed. */
	deviations?: RecordedDeviation[];
};

export function recordPath(chainId: number, dir = DEPLOYMENTS_DIR): string {
	return path.join(dir, `${chainId}.json`);
}

/**
 * The chain's record, or an empty one. With `deployer`, refuses a record another signer wrote: a run
 * by a different key must not silently extend another key's deployment.
 */
export function readRecord(
	chainId: number,
	deployer?: Address,
	dir = DEPLOYMENTS_DIR,
): DeploymentRecord {
	const file = recordPath(chainId, dir);
	if (!fs.existsSync(file))
		return {
			chainId,
			deployer: deployer ?? "0x0000000000000000000000000000000000000000",
			contracts: {},
			upgrades: [],
		};
	const record = JSON.parse(fs.readFileSync(file, "utf8")) as DeploymentRecord;
	if (deployer && record.deployer.toLowerCase() !== deployer.toLowerCase()) {
		throw new Error(
			`${file} was written for deployer ${record.deployer}, not ${deployer}; move it aside before deploying with a new deployer`,
		);
	}
	return record;
}

export function writeRecord(
	record: DeploymentRecord,
	dir = DEPLOYMENTS_DIR,
): string {
	fs.mkdirSync(dir, { recursive: true });
	const file = recordPath(record.chainId, dir);
	fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
	return file;
}

/**
 * Appends the run's deviations to the record. `confirmed` is true when the operator typed the
 * deviation phrase (mainnet). Deviations already recorded for the same contract and address stay.
 */
export function recordDeviations(
	record: DeploymentRecord,
	deviations: readonly {
		key: string;
		reason: DeviationReason;
		expected: Address | null;
		actual: Address | null;
	}[],
	confirmed: boolean,
	at: string = new Date().toISOString(),
): void {
	const existing = record.deviations ?? [];
	for (const d of deviations) {
		if (
			existing.some(
				(e) =>
					e.contract === d.key &&
					e.reason === d.reason &&
					e.actual?.toLowerCase() === d.actual?.toLowerCase(),
			)
		)
			continue;
		existing.push({
			contract: d.key,
			reason: d.reason,
			expected: d.expected,
			actual: d.actual,
			at,
			confirmed,
		});
	}
	if (existing.length) record.deviations = existing;
}
