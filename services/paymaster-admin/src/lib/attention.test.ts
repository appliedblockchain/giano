import type {
	PaymasterOverview,
	TenantView,
	TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { attentionItems, groupAttention } from "./attention";
import type { TenantSummary } from "./platform-api";
import { joinTenants } from "./tenants";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";

const registry = (
	id: string,
	slug: string,
	status: TenantSummary["status"] = "active",
) =>
	({
		id,
		slug,
		status,
		createdAt: "2026-10-01T00:00:00.000Z",
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
				platformApi: true,
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
			platformApi: true,
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
					platformApi: true,
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
				platformApi: false,
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
				stake: {
					staked: true,
					withdrawTime: 100,
				} as PaymasterOverview["stake"],
			}),
			rows,
			ready,
			now: 200,
			platformApi: true,
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
});
