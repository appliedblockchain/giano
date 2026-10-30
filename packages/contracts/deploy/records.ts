/**
 * deployments/<chainId>.json: what is deployed where, written by the deploy CLI and committed for
 * every chain except the local ones. scripts/generate-addresses.ts builds addresses.ts from these.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import type { Address, Hex } from "viem";
import type { LabelKey } from "./config";

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
	/** Absent when the contract was already there when the CLI ran. */
	transactionHash?: Hex;
};

export type DeploymentRecord = {
	chainId: number;
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
};

export function recordPath(chainId: number, dir = DEPLOYMENTS_DIR): string {
	return path.join(dir, `${chainId}.json`);
}

export function readRecord(
	chainId: number,
	deployer: Address,
	dir = DEPLOYMENTS_DIR,
): DeploymentRecord {
	const file = recordPath(chainId, dir);
	if (!fs.existsSync(file))
		return { chainId, deployer, contracts: {}, upgrades: [] };
	const record = JSON.parse(fs.readFileSync(file, "utf8")) as DeploymentRecord;
	if (record.deployer.toLowerCase() !== deployer.toLowerCase()) {
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
