import { describe, expect, it } from "vitest";
import {
	chainPolicyFormProblems,
	chainPolicyToForm,
	describeChainPolicySource,
	describeChainPolicyValue,
	formToChainPolicy,
	overriddenFields,
} from "./chain-policy";
import type { ChainPolicyView } from "./platform-api";
import { parseRoute } from "./router";

const PAYMASTER = "0xb2c7081be89d88f1da020530ebd5c14b8871615a";

describe("chain relay policy form", () => {
	it("round-trips a stored policy, keeping not set, any and only apart", () => {
		const stored = {
			maxCallGas: "5000000",
			maxFeePerGas: "10000000000",
			allowedTargets: "any",
			allowedPaymasters: [PAYMASTER],
		};
		const form = chainPolicyToForm(stored);
		expect(form.allowedTargets).toEqual({ mode: "any", text: "" });
		expect(form.allowedPaymasters).toEqual({ mode: "only", text: PAYMASTER });
		expect(form.maxVerificationGas).toBe("");
		expect(formToChainPolicy(form)).toEqual(stored);
	});

	it("starts a chain with no stored row with every field not set, and sends nothing for them", () => {
		const form = chainPolicyToForm(null);
		expect(form.allowedPaymasters).toEqual({ mode: "default", text: "" });
		expect(formToChainPolicy(form)).toEqual({});
	});

	it("catches an empty 'Only these', a bad address and a cap that is not a whole number", () => {
		const form = chainPolicyToForm(null);
		form.allowedTargets = { mode: "only", text: " \n " };
		form.allowedPaymasters = { mode: "only", text: "0x1234" };
		form.maxCallGas = "1.5";
		const problems = chainPolicyFormProblems(form);
		expect(problems).toHaveLength(3);
		expect(problems.join("\n")).toMatch(
			/Max call gas must be a positive whole number/,
		);
		expect(problems.join("\n")).toMatch(
			/Allowed targets is "Only these" with no address/,
		);
		expect(problems.join("\n")).toMatch(/"0x1234" is not a 0x address/);
		expect(chainPolicyFormProblems(chainPolicyToForm(null))).toEqual([]);
	});
});

describe("chain relay policy display", () => {
	it("shows fees in wei and gwei, allowlists in words, and an undecided field as not set", () => {
		expect(describeChainPolicyValue("maxFeePerGas", "10000000000")).toBe(
			"10000000000 wei (10 gwei)",
		);
		expect(describeChainPolicyValue("maxCallGas", "5000000")).toBe("5,000,000");
		expect(describeChainPolicyValue("allowedTargets", "any")).toBe(
			"any address",
		);
		expect(describeChainPolicyValue("allowedPaymasters", [PAYMASTER])).toBe(
			PAYMASTER,
		);
		expect(describeChainPolicyValue("maxFeePerGas", null)).toBe("not set");
	});

	it("names each source, and locks overridden fields", () => {
		const view: ChainPolicyView = {
			chainId: 8453,
			name: "Base",
			version: 1,
			stored: {},
			updatedAt: null,
			updatedBy: null,
			problems: [],
			fields: {
				maxFeePerGas: {
					effective: "1",
					source: "override",
					overriddenBy: "GIANO_CHAINS",
					stored: null,
				},
				maxCallGas: {
					effective: null,
					source: "undecided",
					overriddenBy: null,
					stored: null,
				},
			},
		};
		expect(describeChainPolicySource(view.fields.maxFeePerGas)).toBe(
			"overridden by GIANO_CHAINS",
		);
		expect(describeChainPolicySource(view.fields.maxCallGas)).toBe(
			"not set: operations refused",
		);
		expect([...overriddenFields(view)]).toEqual(["maxFeePerGas"]);
	});

	it("routes /relay-policy to its tab", () => {
		expect(parseRoute("/relay-policy")).toEqual({ tab: "relay-policy" });
	});
});
