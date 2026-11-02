import { describe, expect, it } from "vitest";
import {
	emptyChain,
	formToPolicy,
	policyProblems,
	policyToForm,
} from "./policy";

const TARGET = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";

describe("policy form", () => {
	it("round-trips a policy, keeping default, any and only apart", () => {
		const policy = {
			maxCallGas: "500000",
			relayRateLimitPerMinute: 30,
			perChain: {
				"84532": {
					maxFeePerGas: "1000",
					allowedTargets: [TARGET],
					allowedPaymasters: [],
				},
				"31337": {},
			},
		};
		const form = policyToForm(policy);
		const chain = (id: string) =>
			form.perChain.find((entry) => entry.chainId === id);
		expect(chain("84532")?.allowedTargets).toEqual({
			mode: "only",
			text: TARGET,
		});
		expect(chain("84532")?.allowedPaymasters).toEqual({
			mode: "any",
			text: "",
		});
		expect(chain("31337")?.allowedTargets).toEqual({
			mode: "default",
			text: "",
		});
		expect(formToPolicy(form)).toEqual(policy);
	});

	it("leaves empty fields out, so they inherit the deployment default", () => {
		expect(formToPolicy(policyToForm({}))).toEqual({});
		const form = policyToForm({});
		form.perChain.push(emptyChain("1"));
		expect(formToPolicy(form)).toEqual({ perChain: { "1": {} } });
	});

	it("splits an allowlist on lines and commas, and sends a bad rate limit as typed", () => {
		const form = policyToForm({});
		form.relayRateLimitPerMinute = "ten";
		form.perChain.push({
			...emptyChain("1"),
			allowedTargets: { mode: "only", text: `${TARGET},\n ${TARGET} \n` },
		});
		expect(formToPolicy(form)).toEqual({
			relayRateLimitPerMinute: "ten",
			perChain: { "1": { allowedTargets: [TARGET, TARGET] } },
		});
	});
});

describe("policyProblems", () => {
	it("refuses Only these with no address, which would be sent as any address", () => {
		const form = policyToForm({});
		form.perChain.push({
			...emptyChain("1"),
			allowedTargets: { mode: "only", text: " \n ," },
		});
		expect(policyProblems(form)).toEqual([
			'Allowed targets on chain 1 is "Only these" with no address. Add one, or choose "Any address" if that is what you mean.',
		]);
	});

	it("refuses a repeated or missing chain id, which would merge or send an empty key", () => {
		const form = policyToForm({});
		form.perChain.push(emptyChain("1"), emptyChain("1"), emptyChain(""));
		expect(policyProblems(form)).toEqual([
			"Chain 1 has two sections: merge them into one.",
			"Each chain section needs a chain id, a whole number.",
		]);
	});

	it("is empty for a well-formed policy", () => {
		expect(
			policyProblems(
				policyToForm({ perChain: { "1": { allowedTargets: [] } } }),
			),
		).toEqual([]);
	});
});
