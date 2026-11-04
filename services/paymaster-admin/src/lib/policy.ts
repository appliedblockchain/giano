/**
 * A tenant's sponsorship policy as form fields (openspec K11), and back.
 *
 * The shape is wallet-api's `tenantPolicySchema` (services/wallet-api/src/services/tenants.ts):
 * gas and fee caps as decimal strings and a relay rate limit, once for every chain, and per chain
 * the same caps plus address allowlists. wallet-api validates on save; this only converts.
 *
 * An allowlist has three meanings, and the form keeps them apart: absent inherits the deployment's
 * default, an empty list allows any address, and a list allows only those. A textarea alone would
 * fold the first two together and silently change one into the other on save.
 */

export const CAP_FIELDS = [
	"maxCallGas",
	"maxVerificationGas",
	"maxFeePerGas",
	"maxPriorityFeePerGas",
] as const;

export type CapField = (typeof CAP_FIELDS)[number];

export const CAP_LABELS: Record<CapField, string> = {
	maxCallGas: "Max call gas",
	maxVerificationGas: "Max verification gas",
	maxFeePerGas: "Max fee per gas (wei)",
	maxPriorityFeePerGas: "Max priority fee per gas (wei)",
};

export const LIST_FIELDS = ["allowedTargets", "allowedPaymasters"] as const;
export type ListField = (typeof LIST_FIELDS)[number];

export const LIST_LABELS: Record<ListField, string> = {
	allowedTargets: "Allowed targets",
	allowedPaymasters: "Allowed paymasters",
};

export type ListMode = "default" | "any" | "only";
export type ListForm = { mode: ListMode; text: string };

type Caps = Record<CapField, string>;

export type PerChainForm = Caps & {
	chainId: string;
} & Record<ListField, ListForm>;

export type PolicyForm = Caps & {
	relayRateLimitPerMinute: string;
	perChain: PerChainForm[];
};

const emptyCaps = (): Caps => ({
	maxCallGas: "",
	maxVerificationGas: "",
	maxFeePerGas: "",
	maxPriorityFeePerGas: "",
});

export function emptyChain(chainId = ""): PerChainForm {
	return {
		chainId,
		...emptyCaps(),
		allowedTargets: { mode: "default", text: "" },
		allowedPaymasters: { mode: "default", text: "" },
	};
}

const text = (value: unknown) =>
	value === undefined || value === null ? "" : String(value);

function capsFrom(source: Record<string, unknown>): Caps {
	return Object.fromEntries(
		CAP_FIELDS.map((field) => [field, text(source[field])]),
	) as Caps;
}

function listFrom(value: unknown): ListForm {
	if (!Array.isArray(value)) return { mode: "default", text: "" };
	if (value.length === 0) return { mode: "any", text: "" };
	return { mode: "only", text: value.join("\n") };
}

export function policyToForm(policy: Record<string, unknown>): PolicyForm {
	const perChain = (policy.perChain ?? {}) as Record<
		string,
		Record<string, unknown>
	>;
	return {
		...capsFrom(policy),
		relayRateLimitPerMinute: text(policy.relayRateLimitPerMinute),
		perChain: Object.entries(perChain).map(([chainId, entry]) => ({
			chainId,
			...capsFrom(entry),
			allowedTargets: listFrom(entry.allowedTargets),
			allowedPaymasters: listFrom(entry.allowedPaymasters),
		})),
	};
}

function capsTo(caps: Caps): Record<string, string> {
	const out: Record<string, string> = {};
	for (const field of CAP_FIELDS) {
		const value = caps[field].trim();
		if (value) out[field] = value;
	}
	return out;
}

function listTo(list: ListForm): string[] | undefined {
	if (list.mode === "default") return undefined;
	if (list.mode === "any") return [];
	return list.text
		.split(/[\n,]/)
		.map((line) => line.trim())
		.filter(Boolean);
}

/**
 * What is wrong with a policy form before it is sent, one sentence each; empty when nothing is.
 *
 * "Only these" with no address would otherwise be sent as an empty list — which wallet-api reads as
 * *any* address, the most permissive allowlist there is, while the form looked locked down. And two
 * sections for one chain would silently merge, the second overwriting the first.
 */
export function policyProblems(form: PolicyForm): string[] {
	const problems: string[] = [];
	const seen = new Set<string>();
	for (const chain of form.perChain) {
		const id = chain.chainId.trim();
		if (!/^\d+$/.test(id))
			problems.push("Each chain section needs a chain id, a whole number.");
		else if (seen.has(id))
			problems.push(`Chain ${id} has two sections: merge them into one.`);
		seen.add(id);
		for (const field of LIST_FIELDS)
			if (chain[field].mode === "only" && !listTo(chain[field])?.length)
				problems.push(
					`${LIST_LABELS[field]} on chain ${id || "?"} is "Only these" with no address. Add one, or choose "Any address" if that is what you mean.`,
				);
	}
	return problems;
}

/**
 * The policy object to send. Empty fields are left out, so they inherit the deployment default.
 * A rate limit that is not a whole number is sent as typed, for wallet-api to refuse against its
 * field rather than to arrive as `null`.
 */
export function formToPolicy(form: PolicyForm): Record<string, unknown> {
	const policy: Record<string, unknown> = capsTo(form);
	const limit = form.relayRateLimitPerMinute.trim();
	if (limit)
		policy.relayRateLimitPerMinute = /^\d+$/.test(limit)
			? Number(limit)
			: limit;

	const perChain: Record<string, unknown> = {};
	for (const chain of form.perChain) {
		const entry: Record<string, unknown> = capsTo(chain);
		for (const field of LIST_FIELDS) {
			const list = listTo(chain[field]);
			if (list) entry[field] = list;
		}
		perChain[chain.chainId.trim()] = entry;
	}
	if (form.perChain.length > 0) policy.perChain = perChain;
	return policy;
}
