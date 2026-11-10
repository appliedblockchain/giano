import type {
	PaymasterOverview,
	TenantView,
	TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { attentionItems, groupAttention, unreadSources } from "./attention";
import type { TenantSummary } from "./platform-api";
import { joinTenants } from "./tenants";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";

const registry = (
	id: string,
	slug: string,
	status: TenantSummary["status"] = "active",
	createdAt = "2026-10-01T00:00:00.000Z",
) =>
	({
		id,
		slug,
		status,
		createdAt,
		users: 0,
	}) as TenantSummary;

const chain = (uuid: string, overrides: Partial<TenantView> = {}): TenantView =>
	({
		id: `0x${uuid.replace(/-/g, "")}`,
		uuid,
		registered: true,
		enabled: true,
		balance: 10n,
		deficit: 0n,
		...overrides,
	}) as TenantView;

const overview = (
	overrides: Partial<PaymasterOverview> = {},
): PaymasterOverview =>
	({
		solvency: { holds: true },
		config: { paused: false },
		stake: { staked: true, withdrawTime: 0 },
		...overrides,
	}) as PaymasterOverview;

/** Everything read: the registry and its deleted tenants, an on-chain roster, no timelock. */
const READ = { registry: { known: true }, rosterOnChain: true } as const;

const keys = (items: ReturnType<typeof attentionItems>) =>
	items.map((item) => item.key);

describe("attentionItems", () => {
	it("is empty when nothing needs an operator", () => {
		const rows = joinTenants([registry(A, "stock")], [chain(A)]);
		expect(
			attentionItems({
				overview: overview(),
				rows,
				ready: [],
				now: 0,
				sources: READ,
			}),
		).toEqual([]);
	});

	it("names tenants by slug and links each to its page", () => {
		const rows = joinTenants(
			[registry(A, "stock")],
			[chain(A, { deficit: 5n })],
		);
		const [item] = attentionItems({
			overview: overview(),
			rows,
			ready: [],
			now: 0,
			sources: READ,
		});
		expect(item).toMatchObject({
			title: "stock is in deficit",
			link: "/tenants/stock",
			severity: "critical",
		});
	});

	it("flags an unregistered, an unfunded and a disagreeing tenant, and an on-chain id with no row", () => {
		const rows = joinTenants(
			[
				registry(A, "new"),
				registry(B, "empty"),
				registry(C, "gone", "suspended"),
			],
			[
				chain(B, { balance: 0n }),
				chain(C),
				chain("44444444-4444-4444-8444-444444444444"),
			],
		);
		expect(
			keys(
				attentionItems({
					overview: overview(),
					rows,
					ready: [],
					now: 0,
					sources: READ,
				}),
			).sort(),
		).toEqual(
			[
				`enabled:${C}`,
				`unfunded:${B}`,
				`unregistered:${A}`,
				"unregistry:44444444-4444-4444-8444-444444444444",
			].sort(),
		);
	});

	it("does not ask for a registry row when the console has no platform API", () => {
		const rows = joinTenants(undefined, [chain(A)]);
		expect(
			attentionItems({
				overview: overview(),
				rows,
				ready: [],
				now: 0,
				sources: { rosterOnChain: true },
			}),
		).toEqual([]);
	});

	it("puts the paymaster's own conditions and deficits before warnings, and ready operations last", () => {
		const rows = joinTenants([registry(A, "new")], []);
		const ready = [
			{
				id: "0xab",
				calls: [
					{
						target: "0x1",
						decoded: { summary: "set the default fee to 1 ETH" },
					},
				],
			},
		] as unknown as TimelockOperation[];
		const items = attentionItems({
			overview: overview({
				config: { paused: true } as PaymasterOverview["config"],
				solvency: { holds: false } as PaymasterOverview["solvency"],
				// unlockStake sets staked to false and a withdrawal time
				stake: {
					staked: false,
					withdrawTime: 100,
				} as PaymasterOverview["stake"],
			}),
			rows,
			ready,
			now: 200,
			sources: READ,
		});
		expect(keys(items)).toEqual([
			"insolvent",
			"paused",
			"stake",
			`unregistered:${A}`,
			"ready:0xab",
		]);
		expect(items[2].title).toBe("The stake is unlocked");
		expect(items[4]).toMatchObject({
			link: "/timelock#0xab",
			detail: "set the default fee to 1 ETH",
		});
	});
});

describe("attentionItems with sources unread or failed", () => {
	const D = "44444444-4444-4444-8444-444444444444";
	const run = (
		sources: Parameters<typeof attentionItems>[0]["sources"],
		rows = joinTenants(undefined, [chain(A), chain(B, { balance: 0n })]),
	) =>
		attentionItems({ overview: overview(), rows, ready: [], now: 0, sources });

	it("says nothing about registry rows until the registry is read, and says it is still reading", () => {
		const sources = { registry: { known: false }, rosterOnChain: true };
		expect(run(sources)).toEqual([]);
		expect(unreadSources(sources)).toEqual(["the tenant registry"]);
	});

	it("turns a failed registry read into an item, and skips the checks that need it", () => {
		expect(
			keys(
				run({ registry: { known: false, error: "502" }, rosterOnChain: true }),
			),
		).toEqual(["unread:registry"]);
	});

	it("does not call a missing row unknown to the registry while the deleted tenants are unread", () => {
		const rows = joinTenants([registry(A, "stock")], [chain(A), chain(D)]);
		expect(
			keys(
				run(
					{
						registry: { known: true, deletedError: "timeout" },
						rosterOnChain: true,
					},
					rows,
				),
			),
		).toEqual(["unread:deleted"]);
	});

	it("turns a failed timelock read into an item, and waits for one still reading", () => {
		const rows = joinTenants([registry(A, "stock")], [chain(A)]);
		expect(
			keys(
				run(
					{
						...READ,
						timelock: { settled: true, read: false, error: "range" },
					},
					rows,
				),
			),
		).toEqual(["unread:timelock"]);
		expect(
			unreadSources({
				...READ,
				timelock: { settled: false, read: false },
			}),
		).toEqual(["the timelock"]);
	});

	it("waits for the chains' status, and turns a failed read into an item", () => {
		const rows = joinTenants([registry(A, "stock")], [chain(A)]);
		expect(
			unreadSources({
				...READ,
				chains: { pending: true, read: false },
			}),
		).toEqual(["the chains"]);
		expect(
			keys(
				run(
					{ ...READ, chains: { pending: false, read: false, error: "502" } },
					rows,
				),
			),
		).toEqual(["unread:chains"]);
	});

	it("flags active but disabled, and deleted but still enabled, as such", () => {
		const rows = joinTenants(
			[registry(A, "off"), registry(B, "gone", "deleted")],
			[chain(A, { enabled: false }), chain(B)],
		);
		const items = run(READ, rows);
		expect(items.map((item) => [item.key, item.severity])).toEqual([
			[`enabled:${B}`, "critical"],
			[`disabled:${A}`, "warning"],
		]);
	});

	it("does not ask to fund a tenant being wound down", () => {
		const rows = joinTenants(
			[registry(A, "paused", "suspended")],
			[chain(A, { deficit: 3n, enabled: false })],
		);
		expect(run(READ, rows)[0]).toMatchObject({
			key: `deficit:${A}`,
			severity: "warning",
			linkLabel: "Open",
		});
	});

	it("does not call a tenant unregistered without an on-chain roster", () => {
		const rows = joinTenants([registry(A, "new")], []);
		expect(run({ ...READ, rosterOnChain: false }, rows)).toEqual([]);
	});

	it("lists Health's failures it does not already state, once", () => {
		const rows = joinTenants([registry(A, "stock")], [chain(A)]);
		const health = [
			{ id: "signers", level: "fail", label: "no signing key", detail: "d" },
			{ id: "paused", level: "fail", label: "paused", detail: "d" },
			{ id: "deposit", level: "warn", label: "deposit low", detail: "d" },
		] as const;
		expect(keys(run({ ...READ, health }, rows))).toEqual(["health:signers"]);
	});

	it("names the newest tenants first", () => {
		const rows = joinTenants(
			[
				registry(A, "old", "active", "2026-01-01T00:00:00.000Z"),
				registry(B, "new", "active", "2026-03-01T00:00:00.000Z"),
			],
			[],
		);
		expect(keys(run(READ, rows))).toEqual([
			`unregistered:${B}`,
			`unregistered:${A}`,
		]);
	});
});

describe("groupAttention", () => {
	const item = (kind: string, subject: string) => ({
		key: `${kind}:${subject}`,
		kind,
		subject,
		severity: "warning" as const,
		title: `${subject} has no balance`,
		detail: "It cannot be sponsored until it is funded.",
		link: `/tenants/${subject}`,
		linkLabel: "Fund",
	});

	it("keeps up to three of a kind one by one", () => {
		const items = ["a", "b", "c"].map((name) => item("unfunded", name));
		expect(groupAttention(items)).toEqual(items);
	});

	it("folds more than three into one line where the first was, naming the first few", () => {
		const first = {
			...item("insolvent", "x"),
			subject: undefined,
			key: "insolvent",
		};
		const items = [
			first,
			...["a", "b", "c", "d", "e"].map((name) => item("unfunded", name)),
		];
		const grouped = groupAttention(items);
		expect(grouped).toHaveLength(2);
		expect(grouped[1]).toMatchObject({
			key: "group:unfunded",
			title: "5 tenants have no balance",
			detail:
				"They are registered and enabled, but nothing they do can be sponsored until they are funded.",
			members: [
				{ name: "a", link: "/tenants/a" },
				{ name: "b", link: "/tenants/b" },
				{ name: "c", link: "/tenants/c" },
			],
			more: 2,
			link: "/tenants",
			linkLabel: "Tenants",
		});
	});

	it("puts an empty or nearly empty bundler executor first, and not one that is merely low", () => {
		const executor = (address: string, balanceWei: string) => ({
			address,
			balanceWei,
			busy: false,
			latestNonce: 0,
			pendingNonce: 0,
		});
		const items = attentionItems({
			overview: overview(),
			rows: [],
			ready: [],
			now: 0,
			sources: READ,
			chain: {
				chainId: 84532,
				name: "Base Sepolia",
				bundler: {
					reachable: true,
					entryPointSupported: true,
					// 1 gwei × 400,000 gas = 0.0004 ETH a submission
					gasPriceWei: "1000000000",
					executors: [
						executor("0x90F79bf6EB2c4f870365E785982E1f101E93b906", "0"),
						executor(
							"0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
							"2000000000000000", // 5 submissions
						),
						executor(
							"0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
							"20000000000000000", // 50: low, not urgent
						),
					],
				},
			} as never,
		});
		expect(keys(items)).toEqual([
			"executor:0x90f79bf6eb2c4f870365e785982e1f101e93b906",
			"executor:0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
		]);
		expect(items[0]).toMatchObject({
			severity: "critical",
			title: "Bundler executor 0x90F7…b906 is empty",
			link: "/health",
		});
		expect(items[1].detail).toContain("About 5 submissions left");
	});
});
