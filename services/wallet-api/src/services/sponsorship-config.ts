import type { Address, Hex } from "viem";
import { isAddress, toFunctionSelector } from "viem";
import { z } from "zod";

/**
 * A tenant's sponsorship settings, and the shape of its rules.
 *
 * The settings (`enabled`, the caps, wallet management) are one value per tenant and chain. The
 * rules that name contracts are records of their own (`tenant_sponsorship_rules`, openspec
 * sponsorship-rules-api), so a tenant can add one without rewriting the others. `allowlist` is
 * still accepted in the settings for one minor release, as a deprecated way to write the rules
 * that have no client reference, and is stored as their mirror.
 *
 * Deny-by-default is enforced in three places, on purpose: the defaults here, the
 * `sponsorship-enabled` rule in the engine, and the absence of a row in the database. A tenant
 * with no configuration, an empty one, or one that fails to parse gets *no sponsorship* — never
 * unrestricted sponsorship.
 *
 * There is deliberately no way to express "any contract". `functions: 'all'` covers the
 * legitimate need — allowing a contract without enumerating its ABI — while keeping the target
 * set explicit.
 *
 * `walletManagement` is the single exception to deny-by-default, and the exception is the
 * requirement: wallet management must be sponsored, so it is governed by platform policy rather
 * than by anything a tenant might leave out of a list. See the field's own note.
 */

const addressSchema = z
	.string()
	.refine(
		(value) => isAddress(value),
		"must be a 0x-prefixed 20-byte hex address",
	)
	.transform((value) => value.toLowerCase() as Address);

/** wei as a decimal string: a bigint does not survive JSON, and a number loses precision. */
const weiSchema = z
	.string()
	.regex(/^[0-9]+$/, "must be a non-negative decimal string of wei")
	.refine((value) => value.length <= 40, "implausibly large");

const selectorSchema = z
	.string()
	.regex(/^0x[0-9a-fA-F]{8}$/, "must be a 4-byte selector");

/**
 * Either a raw selector or a human-readable signature. Signatures are normalised to selectors at
 * write time, so a rules evaluation never does string work on a hot path.
 */
const functionSchema = z
	.union([selectorSchema, z.string().min(3)])
	.transform((value, ctx) => {
		if (/^0x[0-9a-fA-F]{8}$/.test(value)) return value.toLowerCase() as Hex;
		try {
			return toFunctionSelector(value);
		} catch {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `not a selector or a function signature: ${value}. Expected e.g. "transfer(address,uint256)" or "0xa9059cbb"`,
			});
			return z.NEVER;
		}
	});

/** 'all' allows every function on the contract; an array restricts to those selectors. */
export const ruleFunctionsSchema = z.union([
	z.literal("all"),
	z.array(functionSchema).min(1),
]);

const allowlistEntrySchema = z.object({
	contract: addressSchema,
	functions: ruleFunctionsSchema,
});

/** A tenant's own reference for a rule: what it calls the payment or deployment the rule is for. */
const clientReferenceSchema = z
	.string()
	.regex(
		/^[A-Za-z0-9._:-]{1,128}$/,
		"must be 1 to 128 characters from A-Z a-z 0-9 . _ : -",
	);

const expiresAtSchema = z
	.string()
	.datetime({ offset: true })
	.transform((value) => new Date(value));

/** The body of `POST /v1/admin/sponsorship/rules`. */
export const ruleCreateSchema = z
	.object({
		contract: addressSchema,
		functions: ruleFunctionsSchema,
		clientReference: clientReferenceSchema.optional(),
		expiresAt: expiresAtSchema.optional(),
	})
	.strict();

export type RuleCreate = z.infer<typeof ruleCreateSchema>;

/**
 * The body of `PATCH /v1/admin/sponsorship/rules/:id`. The contract and the client reference name
 * what the rule is for, so they cannot change: a different contract is a different rule.
 */
export const rulePatchSchema = z
	.object({
		functions: ruleFunctionsSchema.optional(),
		/** `null` removes the expiry. */
		expiresAt: expiresAtSchema.nullable().optional(),
	})
	.strict()
	.refine(
		(patch) => patch.functions !== undefined || patch.expiresAt !== undefined,
		"must change functions or expiresAt",
	);

export type RulePatch = z.infer<typeof rulePatchSchema>;

/** What the rules engine needs of a rule: which contract, which functions, and its id to record. */
export type SponsorshipRule = {
	id: string;
	contract: Address;
	functions: "all" | Hex[];
};

export const sponsorshipConfigSchema = z
	.object({
		/** A new tenant sponsors nothing until it says otherwise. */
		enabled: z.boolean().default(false),
		maxCostPerTxWei: weiSchema.optional(),
		/**
		 * Deprecated. The rules that have no client reference, written as one array. A write that
		 * carries it replaces those rules; the stored value mirrors them. Evaluation never reads it.
		 */
		allowlist: z.array(allowlistEntrySchema).optional(),
		/**
		 * Adding a passkey or recovering an account is precisely the moment a user is least likely to
		 * hold a native token: a new device has no native token on it and no way to acquire any, so an
		 * unsponsored recovery path does not work for the users who need it.
		 *
		 * This is therefore the one field whose default is *permissive*, and it is the only one that
		 * should be. Its absence means sponsored, because a tenant must not be able to break account
		 * recovery by forgetting a key. `enabled: false` is a deliberate statement, recorded in the
		 * config history like any other. The cap is the platform's; a tenant may only lower it.
		 */
		walletManagement: z
			.object({
				enabled: z.boolean().default(true),
				maxCostPerTxWei: weiSchema.optional(),
			})
			.optional(),
		/** Per-tenant low-balance alert threshold; falls back to the deployment default. */
		lowBalanceThresholdWei: weiSchema.optional(),
	})
	.strict()
	.superRefine((config, ctx) => {
		if (!config.enabled) return;

		if (!config.maxCostPerTxWei) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ["maxCostPerTxWei"],
				message:
					"required when sponsorship is enabled — an uncapped transaction cost is not a rule set",
			});
		}
	})
	.superRefine((config, ctx) => {
		const seen = new Set<string>();
		for (const [index, entry] of (config.allowlist ?? []).entries()) {
			if (seen.has(entry.contract)) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					path: ["allowlist", index, "contract"],
					message: `duplicate entry for ${entry.contract} — merge the function lists instead, so which one wins is not a question`,
				});
			}
			seen.add(entry.contract);
		}
	});

export type SponsorshipConfig = z.infer<typeof sponsorshipConfigSchema>;

/** The configuration a tenant with no row (or an unparseable one) gets: nothing. */
export const DENY_ALL_SPONSORSHIP: SponsorshipConfig = {
	enabled: false,
};

/** True unless the tenant has explicitly said otherwise. Absent config means sponsored. */
export function walletManagementEnabled(config: SponsorshipConfig): boolean {
	return config.walletManagement?.enabled ?? true;
}

/**
 * Rejects a tenant cap above the platform's.
 *
 * Kept out of the schema on purpose: the platform cap is service configuration, and
 * `parseSponsorshipConfig` must be able to read a stored row back without knowing it — a row
 * written when the cap was higher has to degrade to the *current* cap (which the rules engine does
 * by taking the lower of the two), not fail to parse and take the tenant's whole configuration
 * down with it. On the write path a too-high value is an error rather than a silent clamp, because
 * a tenant that asked for a cap and got a different one should be told.
 */
export function checkWalletManagementCap(
	config: SponsorshipConfig,
	platformCapWei: bigint,
): Array<{ path: string; message: string }> {
	const requested = config.walletManagement?.maxCostPerTxWei;
	if (requested === undefined) return [];
	if (BigInt(requested) <= platformCapWei) return [];
	return [
		{
			path: "walletManagement.maxCostPerTxWei",
			message:
				`must not exceed the platform cap of ${platformCapWei} wei — wallet management is governed by platform ` +
				"policy, not by the tenant, so this value may only lower the cap and never raise it",
		},
	];
}

export type ParsedSponsorshipConfig =
	| { ok: true; config: SponsorshipConfig }
	| { ok: false; config: SponsorshipConfig; issues: string[] };

/**
 * Reads a stored configuration back.
 *
 * Re-validated rather than trusted: a row written by an older schema, or corrupted by hand, must
 * degrade to *no sponsorship*. Interpreting an unparseable rule set permissively is the failure
 * mode this whole design exists to avoid, so the caller gets a deny-all config and the issues to
 * log — never a throw it might catch and shrug off.
 */
export function parseSponsorshipConfig(raw: unknown): ParsedSponsorshipConfig {
	const result = sponsorshipConfigSchema.safeParse(raw);
	if (result.success) return { ok: true, config: result.data };
	return {
		ok: false,
		config: DENY_ALL_SPONSORSHIP,
		issues: result.error.issues.map(
			(issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`,
		),
	};
}

/** Formats zod issues for a 400 body, so a tenant can see exactly which field it got wrong. */
export function formatConfigIssues(
	error: z.ZodError,
): Array<{ path: string; message: string }> {
	return error.issues.map((issue) => ({
		path: issue.path.join(".") || "(root)",
		message: issue.message,
	}));
}
