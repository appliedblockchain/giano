import { and, desc, eq, lt } from "drizzle-orm";
import { z } from "zod";
import type { ResolvedChain } from "../config.js";
import type { Db } from "../db/index.js";
import { chainRelayPolicy, chainRelayPolicyHistory } from "../db/schema.js";
import { FALLBACK_FEE_CAPS, KNOWN_CHAIN_FEE_CAPS } from "./chain-fee-caps.js";

/**
 * Each chain's relay policy (openspec change chain-relay-policy-console).
 *
 * A chain's caps and allowlists live in the `chain_relay_policy` table, seeded with safe values for
 * every served chain at boot (design D3) and edited by platform admins. A chain descriptor's
 * `walletApi.policy` (GIANO_CHAINS) and the `USEROP_*` env vars override it field by field (D2). A
 * field nothing decides is *undecided*: outside production it falls back to the permissive
 * behaviour wallet-api had before, in production it refuses every operation on the chain under the
 * `chain-policy` rule (D4). A tenant's own policy applies on top, as before (tenants.ts).
 */

export const CHAIN_CAP_FIELDS = [
	"maxCallGas",
	"maxVerificationGas",
	"maxPreVerificationGas",
	"maxPaymasterVerificationGas",
	"maxPaymasterPostOpGas",
	"maxFeePerGas",
	"maxPriorityFeePerGas",
] as const;
export const CHAIN_LIST_FIELDS = [
	"allowedTargets",
	"allowedPaymasters",
] as const;
export const CHAIN_POLICY_FIELDS = [
	...CHAIN_CAP_FIELDS,
	...CHAIN_LIST_FIELDS,
] as const;

export type ChainCapField = (typeof CHAIN_CAP_FIELDS)[number];
export type ChainListField = (typeof CHAIN_LIST_FIELDS)[number];
export type ChainPolicyField = (typeof CHAIN_POLICY_FIELDS)[number];

/** An allowlist as the relay reads it: `"any"`, or lowercase addresses. */
export type Allowlist = "any" | string[];

/** The env var that overrides each field, for a deployment that sets it. */
export const CHAIN_POLICY_ENV: Record<ChainPolicyField, string> = {
	maxCallGas: "USEROP_MAX_CALL_GAS",
	maxVerificationGas: "USEROP_MAX_VERIFICATION_GAS",
	maxPreVerificationGas: "USEROP_MAX_PRE_VERIFICATION_GAS",
	maxPaymasterVerificationGas: "USEROP_MAX_PAYMASTER_VERIFICATION_GAS",
	maxPaymasterPostOpGas: "USEROP_MAX_PAYMASTER_POST_OP_GAS",
	maxFeePerGas: "USEROP_MAX_FEE_PER_GAS",
	maxPriorityFeePerGas: "USEROP_MAX_PRIORITY_FEE_PER_GAS",
	allowedTargets: "USEROP_ALLOWED_TARGETS",
	allowedPaymasters: "USEROP_ALLOWED_PAYMASTERS",
};

/** One overridden field: its value and where it was set (`GIANO_CHAINS` or an env var's name). */
export type ChainPolicyOverride<V> = { value: V; source: string };

/** What the deployment's configuration sets for one chain; each field it sets wins over the database. */
export type ChainPolicyOverrides = {
	[F in ChainCapField]?: ChainPolicyOverride<bigint>;
} & {
	[F in ChainListField]?: ChainPolicyOverride<Allowlist>;
};

// ── The stored policy ─────────────────────────────────────────────────────────────

const capSchema = z
	.string()
	.regex(/^[1-9]\d*$/, "must be a positive integer, as a decimal string");

const allowlistSchema = z
	.union(
		[
			z.literal("any"),
			z
				.array(z.string().regex(/^0x[0-9a-fA-F]{40}$/, "expected a 0x address"))
				.min(
					1,
					'an empty list is not a choice: send "any" to allow any address, or the addresses allowed',
				),
		],
		{ error: 'expected "any" or a non-empty list of 0x addresses' },
	)
	.transform(
		(value): Allowlist =>
			value === "any" ? value : value.map((a) => a.toLowerCase()),
	);

/**
 * A chain's stored relay policy: the shape of a descriptor's `walletApi.policy`, except that an
 * empty allowlist is refused (G6). Every field is optional: absent is undecided. Strict, so a typo
 * is refused rather than read as "not set".
 */
export const storedChainPolicySchema = z
	.object({
		maxCallGas: capSchema.optional(),
		maxVerificationGas: capSchema.optional(),
		maxPreVerificationGas: capSchema.optional(),
		maxPaymasterVerificationGas: capSchema.optional(),
		maxPaymasterPostOpGas: capSchema.optional(),
		maxFeePerGas: capSchema.optional(),
		maxPriorityFeePerGas: capSchema.optional(),
		allowedTargets: allowlistSchema.optional(),
		allowedPaymasters: allowlistSchema.optional(),
	})
	.strict();

export type StoredChainPolicy = z.output<typeof storedChainPolicySchema>;

// ── Seed ──────────────────────────────────────────────────────────────────────────

/** The gas caps wallet-api has always defaulted to (README, "Relay policy"). */
export const DEFAULT_GAS_CAPS = {
	maxCallGas: 5_000_000n,
	maxVerificationGas: 5_000_000n,
	// generous: on OP Stack chains it carries the L1 data fee in L2 gas
	maxPreVerificationGas: 10_000_000n,
	maxPaymasterVerificationGas: 1_000_000n,
	maxPaymasterPostOpGas: 1_000_000n,
} as const;

/**
 * The policy a chain gets when it has none (design D3). Only values that are safe: the default gas
 * caps, the chain's known fee caps, any target (the relay does not restrict what a wallet does with
 * its own funds), and only the chain's own Giano paymaster. A chain wallet-api has no fee caps or
 * no paymaster for gets those fields undecided, which the console and the relay report (D4).
 */
export function seedChainPolicy(
	chain: Pick<ResolvedChain, "chainId" | "sponsorshipPaymaster">,
): StoredChainPolicy {
	const known = KNOWN_CHAIN_FEE_CAPS[chain.chainId];
	return {
		maxCallGas: String(DEFAULT_GAS_CAPS.maxCallGas),
		maxVerificationGas: String(DEFAULT_GAS_CAPS.maxVerificationGas),
		maxPreVerificationGas: String(DEFAULT_GAS_CAPS.maxPreVerificationGas),
		maxPaymasterVerificationGas: String(
			DEFAULT_GAS_CAPS.maxPaymasterVerificationGas,
		),
		maxPaymasterPostOpGas: String(DEFAULT_GAS_CAPS.maxPaymasterPostOpGas),
		...(known
			? {
					maxFeePerGas: String(known.maxFeePerGas),
					maxPriorityFeePerGas: String(known.maxPriorityFeePerGas),
				}
			: {}),
		allowedTargets: "any",
		...(chain.sponsorshipPaymaster
			? { allowedPaymasters: [chain.sponsorshipPaymaster.toLowerCase()] }
			: {}),
	};
}

// ── Resolution ────────────────────────────────────────────────────────────────────

/**
 * Where a field's effective value comes from: an override (`GIANO_CHAINS` or an env var's name),
 * the stored policy, the non-production fallback, or nowhere (production, refused).
 */
export type FieldSource =
	| { kind: "override"; source: string }
	| { kind: "stored" }
	| { kind: "fallback" }
	| { kind: "undecided" };

export type ResolvedChainPolicy = {
	/** The chain's defaults as the relay applies them; an allowlist of `[]` is no restriction. */
	policy: {
		maxCallGas: bigint;
		maxVerificationGas: bigint;
		maxPreVerificationGas: bigint;
		maxPaymasterVerificationGas: bigint;
		maxPaymasterPostOpGas: bigint;
		maxFeePerGas: bigint;
		maxPriorityFeePerGas: bigint;
		allowedTargets: string[];
		allowedPaymasters: string[];
	};
	/** Each field's effective value as the API shows it, and where it comes from. */
	fields: Record<
		ChainPolicyField,
		{ value: string | Allowlist | null; from: FieldSource }
	>;
	/** Why the chain's operations are refused; empty when they are not (rule `chain-policy`). */
	problems: string[];
};

/** The non-production value of an undecided field: what wallet-api applied before (D4). */
const FALLBACK: Record<ChainPolicyField, bigint | Allowlist> = {
	...DEFAULT_GAS_CAPS,
	...FALLBACK_FEE_CAPS,
	allowedTargets: "any",
	allowedPaymasters: "any",
};

const display = (value: bigint | Allowlist) =>
	typeof value === "bigint" ? String(value) : value;

/**
 * Resolves one chain's policy, field by field (design D2): override, else stored, else undecided.
 * The chain's own Giano paymaster (`ownPaymaster`) is always allowed: a stored list is written
 * once, at the seed, so without this a move to a new paymaster proxy would refuse every sponsored
 * operation on the chain until someone edited the list.
 * An undecided field falls back outside production and is a problem in production. A stored policy
 * that does not parse is a problem in every deployment class: none of its values can be trusted, so
 * the chain's operations are refused rather than relayed under the fallbacks.
 *
 * `stored` is the row's raw jsonb, or `undefined` when the chain has no row.
 */
export function resolveChainPolicy({
	chainId,
	stored,
	overrides,
	production,
	ownPaymaster,
}: {
	chainId: number;
	stored: unknown;
	ownPaymaster?: string;
	overrides: ChainPolicyOverrides;
	production: boolean;
}): ResolvedChainPolicy {
	const problems: string[] = [];
	let decided: StoredChainPolicy = {};
	if (stored === undefined) {
		problems.push(
			`chain ${chainId} has no stored relay policy. wallet-api seeds one when it starts; restart it, or set the policy in the console (Relay policy)`,
		);
	} else {
		const parsed = storedChainPolicySchema.safeParse(stored);
		if (parsed.success) decided = parsed.data;
		else
			problems.push(
				`chain ${chainId}'s stored relay policy is invalid, so its operations are refused: ${parsed.error.issues
					.map(
						(issue) => `${issue.path.join(".") || "policy"}: ${issue.message}`,
					)
					.join("; ")}. Fix it in the console (Relay policy)`,
			);
	}
	// A missing or broken row leaves every field without a stored value; the problem above already
	// refuses the chain, so nothing below adds a second one per field.
	const rowUsable = problems.length === 0;

	const fields = {} as ResolvedChainPolicy["fields"];
	const effective = {} as Record<ChainPolicyField, bigint | Allowlist>;
	for (const field of CHAIN_POLICY_FIELDS) {
		const override = overrides[field];
		const storedValue = decided[field];
		if (override) {
			effective[field] = override.value;
			fields[field] = {
				value: display(override.value),
				from: { kind: "override", source: override.source },
			};
		} else if (storedValue !== undefined) {
			effective[field] =
				typeof storedValue === "string" && storedValue !== "any"
					? BigInt(storedValue)
					: storedValue;
			fields[field] = {
				value: display(effective[field]),
				from: { kind: "stored" },
			};
		} else {
			effective[field] = FALLBACK[field];
			if (production) {
				fields[field] = { value: null, from: { kind: "undecided" } };
				if (rowUsable)
					problems.push(
						`chain ${chainId}: ${field} is not set, so the chain's operations are refused. Set it in the console (Relay policy), or ${CHAIN_POLICY_ENV[field]} / walletApi.policy.${field} in GIANO_CHAINS`,
					);
			} else {
				fields[field] = {
					value: display(FALLBACK[field]),
					from: { kind: "fallback" },
				};
			}
		}
	}

	const list = (value: bigint | Allowlist): string[] =>
		value === "any" ? [] : (value as string[]);
	const paymasters = list(effective.allowedPaymasters);
	const own = ownPaymaster?.toLowerCase();
	if (own && paymasters.length > 0 && !paymasters.includes(own))
		paymasters.push(own);
	const cap = (value: bigint | Allowlist): bigint => value as bigint;
	return {
		policy: {
			maxCallGas: cap(effective.maxCallGas),
			maxVerificationGas: cap(effective.maxVerificationGas),
			maxPreVerificationGas: cap(effective.maxPreVerificationGas),
			maxPaymasterVerificationGas: cap(effective.maxPaymasterVerificationGas),
			maxPaymasterPostOpGas: cap(effective.maxPaymasterPostOpGas),
			maxFeePerGas: cap(effective.maxFeePerGas),
			maxPriorityFeePerGas: cap(effective.maxPriorityFeePerGas),
			allowedTargets: list(effective.allowedTargets),
			allowedPaymasters: paymasters,
		},
		fields,
		problems,
	};
}

// ── Storage ───────────────────────────────────────────────────────────────────────

export type StoredChainPolicyRow = {
	chainId: number;
	policy: unknown;
	version: number;
	updatedAt: Date;
	updatedBy: string;
};

/** A refused write, with the HTTP status and code the platform API answers with. */
export class ChainPolicyWriteError extends Error {
	constructor(
		readonly status: 404 | 412,
		readonly code: "unknown-chain" | "version-mismatch",
		message: string,
		readonly detail: Record<string, unknown> = {},
	) {
		super(message);
		this.name = "ChainPolicyWriteError";
	}
}

export const SEED_ACTOR = "system:seed";

type Logger = {
	info: (obj: object, msg: string) => void;
	error: (obj: object, msg: string) => void;
};

export function createChainPolicyService({
	db,
	chains,
	production,
}: {
	db: Db;
	chains: readonly Pick<
		ResolvedChain,
		"chainId" | "name" | "sponsorshipPaymaster" | "policy"
	>[];
	production: boolean;
}) {
	const chainOf = (chainId: number) =>
		chains.find((chain) => chain.chainId === chainId);

	const rowOf = async (
		chainId: number,
	): Promise<StoredChainPolicyRow | undefined> => {
		const [row] = await db
			.select()
			.from(chainRelayPolicy)
			.where(eq(chainRelayPolicy.chainId, chainId));
		return row;
	};

	const resolve = (
		chain: Pick<ResolvedChain, "chainId" | "policy" | "sponsorshipPaymaster">,
		row: StoredChainPolicyRow | undefined,
	) =>
		resolveChainPolicy({
			chainId: chain.chainId,
			stored: row?.policy,
			overrides: chain.policy,
			production,
			ownPaymaster: chain.sponsorshipPaymaster,
		});

	return {
		/**
		 * Writes the seed for every served chain without a row (design D3), and logs every chain's
		 * problems at error level. Safe to run on several replicas at once: an existing row is never
		 * touched. A database error propagates: a relay must not start without its policy.
		 */
		async seed(log: Logger): Promise<number[]> {
			const seeded: number[] = [];
			for (const chain of chains) {
				const policy = seedChainPolicy(chain);
				const inserted = await db.transaction(async (tx) => {
					const [row] = await tx
						.insert(chainRelayPolicy)
						.values({ chainId: chain.chainId, policy, updatedBy: SEED_ACTOR })
						.onConflictDoNothing()
						.returning({ chainId: chainRelayPolicy.chainId });
					if (!row) return false;
					await tx.insert(chainRelayPolicyHistory).values({
						chainId: chain.chainId,
						action: "seed",
						actor: SEED_ACTOR,
						after: policy,
					});
					return true;
				});
				if (inserted) {
					seeded.push(chain.chainId);
					log.info(
						{ chainId: chain.chainId, policy },
						"seeded the chain's relay policy with its safe defaults",
					);
				}
			}
			for (const chain of chains) {
				const { problems } = resolve(chain, await rowOf(chain.chainId));
				for (const problem of problems)
					log.error(
						{ chainId: chain.chainId, problem },
						"chain relay policy problem: the chain's operations are refused until it is fixed",
					);
			}
			return seeded;
		},

		/** The chain's policy as the relay applies it, read for each operation (design D6). */
		async resolveFor(
			chain: Pick<ResolvedChain, "chainId" | "policy" | "sponsorshipPaymaster">,
		): Promise<ResolvedChainPolicy> {
			return resolve(chain, await rowOf(chain.chainId));
		},

		/** Every served chain, with its row and its resolution, for the platform API. */
		async list() {
			const rows = await db.select().from(chainRelayPolicy);
			return chains.map((chain) => {
				const row = rows.find((r) => r.chainId === chain.chainId);
				return { chain, row, resolved: resolve(chain, row) };
			});
		},

		/**
		 * Replaces a served chain's stored policy, guarded by its version. The caller has validated
		 * `policy` against {@link storedChainPolicySchema}.
		 */
		async replace(
			chainId: number,
			policy: StoredChainPolicy,
			expectedVersion: number,
			actor: { actor: string; platformAdminSessionId: string },
		) {
			const chain = chainOf(chainId);
			if (!chain)
				throw new ChainPolicyWriteError(
					404,
					"unknown-chain",
					`wallet-api does not serve chain ${chainId}`,
				);
			const row = await db.transaction(async (tx) => {
				const [current] = await tx
					.select()
					.from(chainRelayPolicy)
					.where(eq(chainRelayPolicy.chainId, chainId))
					.for("update");
				const currentVersion = current?.version ?? 0;
				if (currentVersion !== expectedVersion)
					throw new ChainPolicyWriteError(
						412,
						"version-mismatch",
						`chain ${chainId}'s relay policy is at version ${currentVersion}, not ${expectedVersion}: someone else changed it. Reload and edit again`,
						{ version: currentVersion },
					);
				const [written] = current
					? await tx
							.update(chainRelayPolicy)
							.set({
								policy,
								version: currentVersion + 1,
								updatedAt: new Date(),
								updatedBy: actor.actor,
							})
							.where(eq(chainRelayPolicy.chainId, chainId))
							.returning()
					: await tx
							.insert(chainRelayPolicy)
							.values({ chainId, policy, updatedBy: actor.actor })
							// With no row, FOR UPDATE above locked nothing: a concurrent first write (or a
							// replica's boot seed) may have inserted it since. That writer won.
							.onConflictDoNothing()
							.returning();
				if (!written) {
					const [winner] = await tx
						.select({ version: chainRelayPolicy.version })
						.from(chainRelayPolicy)
						.where(eq(chainRelayPolicy.chainId, chainId));
					const version = winner?.version ?? 0;
					throw new ChainPolicyWriteError(
						412,
						"version-mismatch",
						`chain ${chainId}'s relay policy is at version ${version}, not ${expectedVersion}: someone else changed it. Reload and edit again`,
						{ version },
					);
				}
				await tx.insert(chainRelayPolicyHistory).values({
					chainId,
					action: "update",
					actor: actor.actor,
					platformAdminSessionId: actor.platformAdminSessionId,
					before: current?.policy ?? null,
					after: policy,
				});
				return written;
			});
			return { chain, row, resolved: resolve(chain, row) };
		},

		/** The chain's changes, newest first, `limit` per page; `before` is the last entry's id. */
		async history(chainId: number, before: string | undefined, limit: number) {
			const cursor = before
				? (
						await db
							.select({ createdAt: chainRelayPolicyHistory.createdAt })
							.from(chainRelayPolicyHistory)
							.where(eq(chainRelayPolicyHistory.id, before))
					)[0]
				: undefined;
			const entries = await db
				.select()
				.from(chainRelayPolicyHistory)
				.where(
					and(
						eq(chainRelayPolicyHistory.chainId, chainId),
						cursor
							? lt(chainRelayPolicyHistory.createdAt, cursor.createdAt)
							: undefined,
					),
				)
				.orderBy(desc(chainRelayPolicyHistory.createdAt))
				.limit(limit + 1);
			return {
				entries: entries.slice(0, limit),
				next: entries.length > limit ? (entries[limit - 1]?.id ?? null) : null,
			};
		},
		/** Whether wallet-api serves the chain. */
		serves: (chainId: number) => chainOf(chainId) !== undefined,
	};
}

export type ChainPolicyService = ReturnType<typeof createChainPolicyService>;
