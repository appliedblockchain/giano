import { describe, expect, it, vi } from "vitest";
import { applyOwnerChange } from "../src/management/apply-owner-change";
import type {
	SponsorshipPreflight,
	WalletRuntime,
	WalletRuntimes,
} from "../src/runtimes";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;

const notOnThisChain: SponsorshipPreflight = {
	state: "refused",
	reason: "sponsorship-disabled",
	message:
		"sponsorship is unavailable: this tenant is not registered on the paymaster",
	ruleResults: [
		{ rule: "sponsorship-enabled", passed: true },
		{
			rule: "paymaster-tenant",
			passed: false,
			detail: "not registered on the paymaster",
		},
	],
};

const switchedOff: SponsorshipPreflight = {
	state: "refused",
	reason: "sponsorship-disabled",
	message: "sponsorship is switched off for this tenant",
	ruleResults: [
		{
			rule: "sponsorship-enabled",
			passed: false,
			detail: "sponsorship is switched off for this tenant",
		},
	],
};

/** Two deployed chains, 1 then 2, each answering the pre-flight as given. */
function runtimes(preflights: Record<number, SponsorshipPreflight>) {
	const sent: number[] = [];
	const runtimeFor = (chainId: number) =>
		({
			provider: {
				getSmartAccount: () => ({}),
				request: vi.fn(async ({ method }: { method: string }) => {
					if (method === "eth_sendTransaction") {
						sent.push(chainId);
						return "0xhash";
					}
					if (method === "waitForUserOperationReceipt")
						return { success: true };
					return undefined;
				}),
			},
			isAccountDeployed: async () => true,
			checkSponsorship: vi.fn(async () => preflights[chainId]),
		}) as unknown as WalletRuntime;
	const cache = new Map<number, WalletRuntime>();
	const set: WalletRuntimes = {
		servedChainIds: [1, 2],
		runtimeFor: (chainId) => {
			const runtime = cache.get(chainId) ?? runtimeFor(chainId);
			cache.set(chainId, runtime);
			return runtime;
		},
		descriptorFor: (chainId) =>
			({ chainId, name: `Chain ${chainId}` }) as never,
	};
	return { set, sent };
}

const apply = (set: WalletRuntimes) =>
	applyOwnerChange({
		runtimes: set,
		walletAddress: WALLET,
		label: "test",
		buildData: async () => "0x1234",
		onProgress: () => undefined,
	});

describe("applyOwnerChange: sponsorship refusals", () => {
	it("still applies the change on a later chain when the tenant is not live on an earlier one's paymaster", async () => {
		const { set, sent } = runtimes({
			1: notOnThisChain,
			2: { state: "sponsored" },
		});
		const outcome = await apply(set);

		expect(sent).toEqual([2]);
		expect(outcome.appliedChainIds).toEqual([2]);
		expect(outcome.progress.map((row) => row.state)).toEqual([
			"refused",
			"confirmed",
		]);
		// not every chain confirmed, and the refusal is still reported
		expect(outcome.ok).toBe(false);
		expect(outcome.refusal).toEqual(notOnThisChain);
	});

	it("stops at a tenant-wide refusal: no later chain is asked", async () => {
		const { set, sent } = runtimes({
			1: switchedOff,
			2: { state: "sponsored" },
		});
		const outcome = await apply(set);

		expect(sent).toEqual([]);
		expect(set.runtimeFor(2).checkSponsorship).not.toHaveBeenCalled();
		expect(outcome.progress.map((row) => row.state)).toEqual([
			"refused",
			"refused",
		]);
		expect(outcome.refusal).toEqual(switchedOff);
	});
});
