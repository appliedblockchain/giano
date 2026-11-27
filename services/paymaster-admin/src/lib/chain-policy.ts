/**
 * A chain's stored relay policy as form fields, and back (openspec chain-relay-policy-console).
 *
 * The shape is wallet-api's `storedChainPolicySchema` (services/wallet-api/src/services/chain-policy.ts):
 * gas and fee caps as decimal strings, and the two allowlists as `"any"` or addresses. Every field is
 * optional: left out, it is *not set*, which wallet-api reads as a fallback outside production and as
 * a refusal of the chain's operations in production. wallet-api validates on save; this converts, and
 * catches the mistakes worth catching before a round trip.
 */

import { linesToList } from "./format";
import type { ChainPolicyFieldView, ChainPolicyView } from "./platform-api";
import {
	CAP_FIELDS,
	CAP_LABELS,
	type CapField,
	LIST_FIELDS,
	LIST_LABELS,
	type ListField,
	type ListForm,
} from "./policy";

export type { CapField, ListField, ListForm };
export { CAP_FIELDS, CAP_LABELS, LIST_FIELDS, LIST_LABELS };

export type ChainPolicyForm = Record<CapField, string> &
	Record<ListField, ListForm>;

/** "default" on a chain means *not set*: nothing is stored for the field. */
export const CHAIN_LIST_MODE_LABELS = {
	default: "Not set",
	any: "Any address",
	only: "Only these",
} as const;

const text = (value: unknown) =>
	typeof value === "string" || typeof value === "number" ? String(value) : "";

function listFrom(value: unknown): ListForm {
	if (value === "any") return { mode: "any", text: "" };
	if (!Array.isArray(value)) return { mode: "default", text: "" };
	if (value.length === 0) return { mode: "any", text: "" };
	return { mode: "only", text: value.join("\n") };
}

/** The form for a chain's stored policy; a chain with no stored row starts with every field not set. */
export function chainPolicyToForm(
	stored: Record<string, unknown> | null,
): ChainPolicyForm {
	const source = stored ?? {};
	const form = {} as ChainPolicyForm;
	for (const field of CAP_FIELDS) form[field] = text(source[field]);
	for (const field of LIST_FIELDS) form[field] = listFrom(source[field]);
	return form;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** What is wrong with one field, one sentence each; empty when nothing is. */
function fieldProblems(
	form: ChainPolicyForm,
	field: CapField | ListField,
): string[] {
	if ((CAP_FIELDS as readonly string[]).includes(field)) {
		const value = form[field as CapField].trim();
		return value && !/^[1-9]\d*$/.test(value)
			? [
					`${CAP_LABELS[field as CapField]} must be a positive whole number, or empty to leave it not set.`,
				]
			: [];
	}
	const list = form[field as ListField];
	const label = LIST_LABELS[field as ListField];
	if (list.mode !== "only") return [];
	const addresses = linesToList(list.text);
	const problems: string[] =
		addresses.length === 0
			? [
					`${label} is "Only these" with no address. Add one, or choose "Any address" if that is what you mean.`,
				]
			: [];
	for (const address of addresses)
		if (!ADDRESS.test(address))
			problems.push(`${label}: "${address}" is not a 0x address.`);
	return problems;
}

/**
 * The stored policy to send. A field left empty or *not set* is left out. So is a `locked` field
 * (overridden, so shown read-only) whose stored value is invalid: the admin cannot edit it, and
 * keeping it would have wallet-api refuse the whole save. The override applies to it either way.
 */
export function formToChainPolicy(
	form: ChainPolicyForm,
	locked: ReadonlySet<string> = new Set(),
): Record<string, unknown> {
	const policy: Record<string, unknown> = {};
	const keep = (field: CapField | ListField) =>
		!locked.has(field) || fieldProblems(form, field).length === 0;
	for (const field of CAP_FIELDS) {
		const value = form[field].trim();
		if (value && keep(field)) policy[field] = value;
	}
	for (const field of LIST_FIELDS) {
		if (!keep(field)) continue;
		const list = form[field];
		if (list.mode === "any") policy[field] = "any";
		else if (list.mode === "only") policy[field] = linesToList(list.text);
	}
	return policy;
}

/**
 * What is wrong with the form before it is sent, one sentence each; empty when nothing is. wallet-api
 * checks the same and more, and its answer is shown too: this only saves a round trip. `locked`
 * fields are skipped: they cannot be edited here, and {@link formToChainPolicy} drops an invalid one.
 */
export function chainPolicyFormProblems(
	form: ChainPolicyForm,
	locked: ReadonlySet<string> = new Set(),
): string[] {
	return [...CAP_FIELDS, ...LIST_FIELDS]
		.filter((field) => !locked.has(field))
		.flatMap((field) => fieldProblems(form, field));
}

const GWEI = 1_000_000_000n;
const FEE_FIELDS = new Set<string>(["maxFeePerGas", "maxPriorityFeePerGas"]);

/** A field's value for display: gwei beside a fee in wei, "any address", or the addresses. */
export function describeChainPolicyValue(
	field: string,
	value: ChainPolicyFieldView["effective"],
): string {
	if (value === null) return "not set";
	if (Array.isArray(value)) return value.join(", ");
	if (value === "any") return "any address";
	if (FEE_FIELDS.has(field) && /^\d+$/.test(value)) {
		const wei = BigInt(value);
		const gwei =
			wei % GWEI === 0n
				? String(wei / GWEI)
				: (Number(wei) / Number(GWEI)).toString();
		return `${value} wei (${gwei} gwei)`;
	}
	return /^\d+$/.test(value) ? Number(value).toLocaleString("en-GB") : value;
}

/** Where a field's value comes from, as a short label. */
export function describeChainPolicySource(field: ChainPolicyFieldView): string {
	switch (field.source) {
		case "override":
			return `overridden by ${field.overriddenBy ?? "the deployment"}`;
		case "stored":
			return "stored";
		case "fallback":
			return "not set: fallback outside production";
		case "undecided":
			return "not set: operations refused";
	}
}

/** The fields an env var or GIANO_CHAINS overrides: shown, never editable here (design D5). */
export function overriddenFields(view: ChainPolicyView): Set<string> {
	return new Set(
		Object.entries(view.fields)
			.filter(([, field]) => field.source === "override")
			.map(([name]) => name),
	);
}
