/** Persisted public chain configuration. Secrets are supplied through environment references only. */
import { readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { getAddress, parseEther, zeroAddress } from "viem";
import { z } from "zod";

export const REPO_ROOT = resolve(import.meta.dirname, "../../..");
export const PROFILES_DIR = resolve(REPO_ROOT, "deploy/chains");

const decimal = z.string().regex(/^\d+(\.\d{1,18})?$/);
const uint128 = z
	.string()
	.regex(/^\d+$/)
	.refine((value) => {
		try {
			return BigInt(value) >= 0n && BigInt(value) < 2n ** 128n;
		} catch {
			return false;
		}
	});
const nonzeroAddress = z.string().refine((value) => {
	try {
		return getAddress(value) !== zeroAddress;
	} catch {
		return false;
	}
});
const seconds = z.number().int().min(0);
/**
 * The paymaster timelock this chain publishes (G9 R2): its address once deployed, its proposers (a
 * Safe in production), its executors (empty: anyone may execute a ready operation) and one delay
 * per timelocked function, in seconds. These delays are a promise to tenants.
 */
const timelockSchema = z
	.object({
		address: nonzeroAddress.nullable(),
		proposers: z.array(nonzeroAddress),
		executors: z.array(nonzeroAddress),
		delays: z
			.object({
				minDelay: seconds,
				upgradeToAndCall: seconds,
				grantRole: seconds,
				revokeRole: seconds,
				renounceRole: seconds,
				setTenantWithdrawAddress: seconds,
				setDefaultFee: seconds,
				setTenantFee: seconds,
			})
			.strict(),
	})
	.strict();
export const profileSchema = z
	.object({
		chainId: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
		name: z
			.string()
			.min(1)
			.regex(/^[\p{L}\p{N} ._()-]+$/u),
		// Store a public fallback here. Keyed URLs belong in the environment variable below.
		rpcUrl: z
			.string()
			.url()
			.refine((value) => {
				try {
					const url = new URL(value);
					return (
						["https:", "http:"].includes(url.protocol) &&
						!url.username &&
						!url.password &&
						!url.search &&
						!url.hash
					);
				} catch {
					return false;
				}
			}),
		rpcUrlEnv: z.string().regex(/^[A-Z][A-Z0-9_]*$/),
		release: z.string().regex(/^v\d+$/),
		roleAdmin: z
			.string()
			.refine((value) => {
				try {
					return getAddress(value) !== zeroAddress;
				} catch {
					return false;
				}
			})
			.nullable(),
		minDeployerBalanceEth: decimal.refine((value) => {
			try {
				return parseEther(value) > 0n;
			} catch {
				return false;
			}
		}),
		paymaster: z
			.object({
				defaultFeeWei: uint128,
				postOpGasAllowance: z
					.number()
					.int()
					.min(0)
					.max(2 ** 32 - 1),
				penaltyBps: z.number().int().min(0).max(5000),
			})
			.strict(),
		timelock: timelockSchema.optional(),
	})
	.strict();
export type ChainProfile = z.infer<typeof profileSchema>;
export type ProfileFile = { file: string; id: string; profile: ChainProfile };

export function listProfiles(): string[] {
	return readdirSync(PROFILES_DIR)
		.filter((name) => /^[a-z0-9][a-z0-9-]*\.json$/.test(name))
		.map((name) => name.slice(0, -5))
		.sort();
}
export function loadProfile(options: {
	chain?: string;
	config?: string;
}): ProfileFile {
	if (Boolean(options.chain) === Boolean(options.config))
		throw new Error(
			"Choose exactly one of --chain <profile> or --config <file>.",
		);
	if (options.chain && !/^[a-z0-9][a-z0-9-]*$/.test(options.chain))
		throw new Error(
			"Use a profile name listed in deploy/chains/, without a file path.",
		);
	const file = options.config
		? resolve(REPO_ROOT, options.config)
		: resolve(PROFILES_DIR, `${options.chain}.json`);
	try {
		return {
			file,
			id: basename(file, ".json"),
			profile: profileSchema.parse(JSON.parse(readFileSync(file, "utf8"))),
		};
	} catch {
		// Do not print parser errors: an operator may accidentally paste a credential into a field.
		throw new Error(
			"Cannot read chain profile. Provide valid JSON matching deploy/chains/*.json: chainId, name, public rpcUrl, rpcUrlEnv, release, roleAdmin, minimum balance, paymaster parameters and optionally the timelock. Unknown/secret fields are refused.",
		);
	}
}

/** Only public choices are persisted; a runtime --rpc or environment override is never copied. */
export function savePublicChoices(
	selected: ProfileFile,
	admin: string,
	release: string,
): void {
	const profile = profileSchema.parse({
		...selected.profile,
		roleAdmin: getAddress(admin),
		release,
	});
	const temporary = `${selected.file}.${process.pid}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(profile, null, "\t")}\n`, {
		flag: "wx",
	});
	renameSync(temporary, selected.file);
}
/** Persists the deployed timelock's address (a public value) into the profile. */
export function saveTimelockAddress(
	selected: ProfileFile,
	address: string,
): void {
	if (!selected.profile.timelock)
		throw new Error(
			"the profile has no timelock section to record the address in",
		);
	const profile = profileSchema.parse({
		...selected.profile,
		timelock: { ...selected.profile.timelock, address: getAddress(address) },
	});
	const temporary = `${selected.file}.${process.pid}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(profile, null, "\t")}\n`, {
		flag: "wx",
	});
	renameSync(temporary, selected.file);
}

export function paymasterParams(profile: ChainProfile) {
	return {
		...profile.paymaster,
		defaultFeeWei: BigInt(profile.paymaster.defaultFeeWei),
	};
}
