import {
	formatDuration,
	type GianoPaymasterClient,
	type PaymasterOverview,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Box,
	DataList,
	HStack,
	SimpleGrid,
	Spinner,
	Stack,
	Text,
} from "@chakra-ui/react";
import type { ReactNode } from "react";
import { LuArrowRight, LuClock } from "react-icons/lu";
import { InlineError, StatusText } from "../components/status";
import { SectionCard } from "../components/ui";
import { UsageCard, useUsage } from "../components/usage";
import { AddressLabel, Amount } from "../components/values";
import { getAdminConfig } from "../config";
import { useChains } from "../hooks/useChains";
import { useImplementation } from "../hooks/useImplementation";
import {
	type AttentionItem,
	type AttentionSources,
	attentionItems,
	groupAttention,
	unreadSources,
} from "../lib/attention";
import type { ConsoleHealth } from "../lib/health";
import { relativeTime } from "../lib/proposals";
import { Link, TAB_PATHS } from "../lib/router";
import type { TenantRow } from "../lib/tenants";
import { useConsole } from "../shell/ConsoleContext";
import { useNow } from "../shell/Header";
import type { Registry } from "../tenants/useRegistry";

/**
 * The Overview (openspec K1, N10): first what needs an operator, each with a link to where it is
 * fixed; then the money, the solvency invariant, the configuration and what is queued. Tenants are
 * named by slug wherever the registry has one.
 */
export function OverviewTab({
	client,
	overview,
	rows,
	registry,
	rosterOnChain,
	health,
}: {
	client: GianoPaymasterClient;
	overview: PaymasterOverview;
	rows: readonly TenantRow[];
	registry: Registry;
	rosterOnChain: boolean;
	health: ConsoleHealth | undefined;
}) {
	const { timelock, timelockOperations, deployment } = useConsole();
	const { platformApi } = getAdminConfig();
	const chains = useChains(platformApi);
	const now = useNow(30_000) / 1000;
	const sources: AttentionSources = {
		registry: platformApi
			? {
					known: registry.tenants !== undefined,
					error: registry.error,
					deletedError: registry.deletedError,
				}
			: undefined,
		timelock: timelock
			? {
					settled: timelockOperations.settled,
					read: timelockOperations.read,
					error: timelockOperations.error,
				}
			: undefined,
		rosterOnChain,
		health: health?.checks,
		// The executors come from wallet-api's chain status: until it is read, all is not known well.
		healthPending: [
			...(health?.pending.map((entry) => entry.label) ?? []),
			...(chains.pending ? ["the chains"] : []),
		],
	};
	const items = groupAttention(
		attentionItems({
			overview,
			rows,
			ready: timelockOperations.pending.filter(
				(operation) => operation.state === "ready",
			),
			now,
			sources,
			chain: chains.status?.chains.find(
				(entry) => entry.chainId === deployment.chainId,
			),
		}),
	);
	const { solvency, stake } = overview;
	const onChain = rows.filter((row) => row.onChain).length;

	return (
		<Stack gap="4">
			<NeedsAttention items={items} sources={sources} />

			<SimpleGrid columns={{ base: 1, sm: 2, xl: 4 }} gap="4">
				<Tile
					label="Deposit"
					hint="at the EntryPoint: what pays for sponsored gas"
				>
					<Amount wei={solvency.depositWei} />
				</Tile>
				<Tile
					label="Tenant balances"
					hint={`${onChain} tenant${onChain === 1 ? "" : "s"} on this chain`}
					link={TAB_PATHS.tenants}
				>
					<Amount wei={solvency.tenantBalancesWei} />
				</Tile>
				<Tile
					label="Treasury"
					hint="platform fees accrued"
					link={TAB_PATHS.paymaster}
				>
					<Amount wei={solvency.treasuryWei} />
				</Tile>
				<Tile
					label="Stake"
					hint={
						stake.staked
							? `unstake delay ${formatDuration(stake.unstakeDelaySec)}`
							: "not staked: bundlers refuse the paymaster"
					}
					link={TAB_PATHS.paymaster}
				>
					<Amount wei={stake.stakeWei} />
				</Tile>
			</SimpleGrid>

			<SimpleGrid columns={{ base: 1, lg: 2 }} gap="4" alignItems="start">
				<SolvencyCard overview={overview} />
				<ConfigurationCard client={client} overview={overview} />
			</SimpleGrid>

			<OverviewUsage />

			<QueuedCard />
		</Stack>
	);
}

const TONE = { critical: "red", warning: "orange" } as const;

function NeedsAttention({
	items,
	sources,
}: {
	items: readonly AttentionItem[];
	sources: AttentionSources;
}) {
	const unread = unreadSources(sources);
	// Nothing found is not nothing wrong until every source has been read.
	if (items.length === 0 && unread.length > 0)
		return (
			<HStack
				gap="3"
				flexWrap="wrap"
				borderWidth="1px"
				rounded="lg"
				bg="surface"
				px="4"
				py="3"
				fontSize="sm"
				data-testid="needs-attention"
			>
				<Spinner size="xs" />
				<Text color="fg.muted">
					Nothing found so far; still reading {unread.join(" and ")}.
				</Text>
			</HStack>
		);
	if (items.length === 0)
		return (
			<HStack
				gap="3"
				flexWrap="wrap"
				borderWidth="1px"
				rounded="lg"
				bg="surface"
				px="4"
				py="3"
				fontSize="sm"
				data-testid="needs-attention"
			>
				<StatusText tone="green">Nothing needs attention</StatusText>
				<Text color="fg.muted">
					The invariant holds, the paymaster is staked and accepting work, every
					tenant is funded
					{sources.registry ? " and agrees with the registry" : ""}
					{sources.timelock
						? ", and nothing in the timelock is waiting on you."
						: "."}
				</Text>
			</HStack>
		);
	return (
		<SectionCard
			title={`Needs attention (${items.length})`}
			subtitle="Most urgent first. Each links to where it is fixed."
		>
			<Stack gap="0" data-testid="needs-attention">
				{items.map((item, index) => (
					<HStack
						key={item.key}
						justify="space-between"
						align="flex-start"
						gap="4"
						py="3"
						borderTopWidth={index === 0 ? "0" : "1px"}
						data-testid={`attention-${item.key}`}
					>
						<Stack gap="1" minW="0">
							<HStack gap="2" flexWrap="wrap">
								{item.severity === "timelock" ? (
									<HStack gap="1.5" color="timelock.fg" fontSize="sm">
										<LuClock aria-hidden="true" />
										<Text as="span" fontWeight="medium">
											{item.title}
										</Text>
									</HStack>
								) : (
									<StatusText tone={TONE[item.severity]}>
										<Text as="span" fontWeight="medium">
											{item.title}
										</Text>
									</StatusText>
								)}
							</HStack>
							{item.members && item.members.length > 0 && (
								<Text fontSize="sm">
									{item.members.map((member, at) => (
										<Text as="span" key={member.link}>
											{at > 0 && ", "}
											<Link to={member.link} color="brand.fg">
												{member.name}
											</Link>
										</Text>
									))}
									{item.more ? ` and ${item.more} more` : ""}
								</Text>
							)}
							<Text fontSize="sm" color="fg.muted">
								{item.detail}
							</Text>
						</Stack>
						<Link
							to={item.link}
							fontSize="sm"
							fontWeight="medium"
							color={item.severity === "timelock" ? "timelock.fg" : "brand.fg"}
							display="inline-flex"
							alignItems="center"
							gap="1"
							whiteSpace="nowrap"
						>
							{item.linkLabel} <LuArrowRight aria-hidden="true" />
						</Link>
					</HStack>
				))}
			</Stack>
		</SectionCard>
	);
}

function Tile({
	label,
	hint,
	link,
	children,
}: {
	label: string;
	hint: string;
	link?: string;
	children: ReactNode;
}) {
	const body = (
		<Stack gap="1">
			<Text
				fontSize="xs"
				textTransform="uppercase"
				letterSpacing="wide"
				color="fg.muted"
			>
				{label}
			</Text>
			<Box
				fontSize="2xl"
				fontWeight="semibold"
				fontFamily="mono"
				lineHeight="1.2"
			>
				{children}
			</Box>
			<Text fontSize="xs" color="fg.muted">
				{hint}
			</Text>
		</Stack>
	);
	return (
		<Box borderWidth="1px" rounded="xl" bg="surface" shadow="sm" p="5">
			{body}
			{link && (
				<Link
					to={link}
					fontSize="xs"
					color="brand.fg"
					mt="2"
					display="inline-block"
				>
					Details
				</Link>
			)}
		</Box>
	);
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="36">{label}</DataList.ItemLabel>
			<DataList.ItemValue>
				<Box minW="0">{children}</Box>
			</DataList.ItemValue>
		</DataList.Item>
	);
}

function SolvencyCard({ overview }: { overview: PaymasterOverview }) {
	const { solvency } = overview;
	return (
		<SectionCard
			title="Solvency"
			subtitle="Tenant balances plus the treasury must never exceed the deposit."
		>
			<Stack gap="3">
				<StatusText tone={solvency.holds ? "green" : "red"}>
					{solvency.holds ? "The invariant holds" : "The invariant is breached"}
				</StatusText>
				<DataList.Root orientation="horizontal" size="sm">
					<Fact label="Owed (claims)">
						<Amount wei={solvency.claimsWei} />
					</Fact>
					<Fact label="Deposit">
						<Amount wei={solvency.depositWei} />
					</Fact>
					<Fact label="Slack">
						<Box color={solvency.holds ? undefined : "red.fg"}>
							<Amount wei={solvency.slackWei} />
						</Box>
					</Fact>
				</DataList.Root>
				<Text fontSize="xs" color="fg.muted">
					The EntryPoint also debits the deposit for costs settlement cannot
					see, so the ledger charges a generous upper bound and the difference
					collects here as slack. Slack growing slowly is expected; slack
					shrinking towards zero is not.
				</Text>
			</Stack>
		</SectionCard>
	);
}

function ConfigurationCard({
	client,
	overview,
}: {
	client: GianoPaymasterClient;
	overview: PaymasterOverview;
}) {
	const { block, deployment } = useConsole();
	const { implementation, error, read } = useImplementation(client, block);
	const { config } = overview;
	return (
		<SectionCard
			title="Configuration"
			subtitle="What every sponsorship is priced and checked against."
		>
			<Stack gap="3">
				<DataList.Root orientation="horizontal" size="sm">
					<Fact label="Default fee">
						<Amount wei={config.defaultFeeWei} decimals={6} />
					</Fact>
					<Fact label="Post-op allowance">
						{config.postOpGasAllowance.toLocaleString()} gas
					</Fact>
					<Fact label="Unused-gas penalty">{config.penaltyBps} bps</Fact>
					<Fact label="Accepting work">
						<StatusText tone={config.paused ? "red" : "green"}>
							{config.paused ? "paused" : "yes"}
						</StatusText>
					</Fact>
					<Fact label="Paymaster">
						<AddressLabel address={overview.address} label="Paymaster" />
					</Fact>
					<Fact label="Implementation">
						{implementation ? (
							<AddressLabel address={implementation} label="Implementation" />
						) : (
							!error && <Text color="fg.muted">reading…</Text>
						)}
					</Fact>
					<Fact label="EntryPoint">
						<AddressLabel address={config.entryPoint} label="EntryPoint" />
					</Fact>
					<Fact label="Chain">
						{deployment.name} · {overview.chainId}
					</Fact>
				</DataList.Root>
				{error && (
					<InlineError
						title="Could not read the implementation"
						error={error}
						retry={() => void read()}
					/>
				)}
				<Text fontSize="xs" color="fg.muted">
					The paymaster address is the proxy. It stays the same across upgrades,
					because it is what tenants fund.
				</Text>
			</Stack>
		</SectionCard>
	);
}

/** The chain's last seven days of sponsorship (B4); absent without wallet-api's usage. */
function OverviewUsage() {
	const usage = useUsage();
	const { deployment } = useConsole();
	if (!usage) return null;
	return (
		<UsageCard
			figures={usage.total}
			unknownTenant={usage.unknownTenant}
			title="Usage, last 7 days"
			subtitle={`Every tenant of this deployment on ${deployment.name}, from wallet-api's sponsorship decisions and settlements. Refusals are split by whose they are to fix.`}
		/>
	);
}

function QueuedCard() {
	const { timelock, timelockOperations } = useConsole();
	if (!timelock) return null;
	const { pending, read, settled } = timelockOperations;
	return (
		<SectionCard
			// No count until a read succeeds: "(0)" after a failed one reads as nothing queued.
			title={read ? `Queued changes (${pending.length})` : "Queued changes"}
			subtitle="Waiting out the timelock's delay, or ready to execute."
		>
			{timelockOperations.error && (
				<InlineError
					title="Could not read the timelock"
					error={timelockOperations.error}
					retry={() => void timelockOperations.reload()}
					retrying={timelockOperations.loading}
					stale={read}
				/>
			)}
			{pending.length === 0 ? (
				read ? (
					<Text fontSize="sm" color="fg.muted">
						Nothing is queued.
					</Text>
				) : (
					!settled && (
						<Text fontSize="sm" color="fg.muted">
							Reading the timelock…
						</Text>
					)
				)
			) : (
				<Stack gap="0">
					{pending.map((operation, index) => (
						<HStack
							key={operation.id}
							justify="space-between"
							align="flex-start"
							gap="4"
							py="3"
							borderTopWidth={index === 0 ? "0" : "1px"}
						>
							<Stack gap="0.5" minW="0">
								{operation.calls.map((call, position) => (
									<Text
										// biome-ignore lint/suspicious/noArrayIndexKey: a call's position is its identity in a batch
										key={position}
										fontSize="sm"
									>
										{call.decoded?.summary ?? `a call to ${call.target}`}
									</Text>
								))}
								<Text fontSize="xs" color="fg.muted">
									{operation.state === "ready"
										? "ready to execute"
										: operation.readyAt
											? `ready ${relativeTime(operation.readyAt)}`
											: "waiting"}
								</Text>
							</Stack>
							<Link
								to={`${TAB_PATHS.timelock}#${operation.id}`}
								fontSize="sm"
								color="timelock.fg"
								display="inline-flex"
								alignItems="center"
								gap="1"
								whiteSpace="nowrap"
							>
								<LuClock aria-hidden="true" /> Open
							</Link>
						</HStack>
					))}
				</Stack>
			)}
		</SectionCard>
	);
}
