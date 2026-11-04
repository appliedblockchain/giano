import type {
	BlockRange,
	GianoPaymasterClient,
	SponsorshipRecord,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Badge,
	Button,
	HStack,
	Input,
	NativeSelect,
	SimpleGrid,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import {
	type ReactNode,
	useCallback,
	useEffect,
	useMemo,
	useRef,
	useState,
} from "react";
import { LuChevronsDown, LuDownload, LuRefreshCw } from "react-icons/lu";
import {
	AdminEventList,
	useAdminEvents,
	useNamer,
} from "../components/admin-events";
import { InlineError } from "../components/status";
import {
	Copyable,
	notifyError,
	notifySuccess,
	SectionCard,
} from "../components/ui";
import { Amount, TxLink } from "../components/values";
import { useWindows } from "../hooks/useWindows";
import {
	filterSettlements,
	type Outcome,
	settlementsCsv,
	settlementTotals,
} from "../lib/activity";
import { EVENT_GROUPS, type EventGroup, eventGroup } from "../lib/admin-events";
import { Link, tenantPath } from "../lib/router";
import type { TenantRow } from "../lib/tenants";
import { useConsole } from "../shell/ConsoleContext";

/**
 * Settled sponsorships, read a window of blocks at a time (openspec K6, G5).
 *
 * The first read is the window ending at the head; "Look further back" adds the one before it, with
 * no cap on rows; and each console refresh reads only the blocks since the newest one read, keeping
 * every older window already loaded. Filters and totals apply to what is loaded, and so does the CSV.
 *
 * Gas, fee and overhead are separate columns because they answer different questions: what the
 * network cost, what Giano charged, and what settlement could not observe.
 */
export function ActivityTab({
	client,
	rows,
	lastUpdated,
}: {
	client: GianoPaymasterClient;
	rows: readonly TenantRow[];
	lastUpdated: Date | undefined;
}) {
	const { deployment } = useConsole();
	const settlements = useSettlements(client, lastUpdated);
	const [tenant, setTenant] = useState("");
	const [outcome, setOutcome] = useState<Outcome>("all");
	const [account, setAccount] = useState("");

	const names = useMemo(
		() => new Map(rows.map((row) => [row.id, row.registry?.slug])),
		[rows],
	);
	const nameOf = useCallback(
		(uuid: string) => names.get(uuid.toLowerCase()) ?? uuid,
		[names],
	);
	const shown = useMemo(
		() => filterSettlements(settlements.records, { tenant, outcome, account }),
		[settlements.records, tenant, outcome, account],
	);
	const totals = settlementTotals(shown);
	const times = useBlockTimes(client, shown);
	const tenantsSeen = useMemo(
		() => [
			...new Set(
				settlements.records.map((record) => record.uuid.toLowerCase()),
			),
		],
		[settlements.records],
	);

	const exportCsv = () => {
		try {
			const csv = settlementsCsv(shown, {
				tenantName: nameOf,
				blockTime: (block) => times.get(block),
				decimals: deployment.nativeCurrency.decimals,
			});
			const name = `giano-settlements-${deployment.chainId}-${settlements.range?.fromBlock}-${settlements.range?.toBlock}.csv`;
			const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
			const link = document.createElement("a");
			link.href = url;
			link.download = name;
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
			URL.revokeObjectURL(url);
			notifySuccess("Saved the settlements", name);
		} catch (cause) {
			notifyError("Could not save the settlements", cause);
		}
	};

	return (
		<Stack gap="4">
			<SectionCard
				title="Sponsorships"
				subtitle={
					settlements.range
						? `Settled in blocks ${settlements.range.fromBlock}–${settlements.range.toBlock}, newest first. A shortfall becomes a recorded deficit rather than a revert: by then the network has been paid.`
						: "Settled sponsorships, newest first."
				}
				action={
					<HStack gap="2" flexWrap="wrap">
						<Button
							size="sm"
							variant="ghost"
							aria-label="Read new settlements"
							loading={settlements.loading}
							onClick={() => void settlements.refresh()}
						>
							<LuRefreshCw />
						</Button>
						<Button
							size="sm"
							variant="outline"
							disabled={shown.length === 0}
							onClick={exportCsv}
						>
							<LuDownload /> Export CSV
						</Button>
					</HStack>
				}
			>
				<Stack gap="3">
					{settlements.error && (
						<InlineError
							title="Could not read the settlements"
							error={settlements.error}
							retry={() => void settlements.refresh()}
							retrying={settlements.loading}
							stale={settlements.windows.length > 0}
						/>
					)}

					<HStack gap="3" flexWrap="wrap">
						<NativeSelect.Root size="sm" width="auto" minW="44">
							<NativeSelect.Field
								aria-label="Tenant"
								value={tenant}
								onChange={(event) => setTenant(event.currentTarget.value)}
							>
								<option value="">Every tenant</option>
								{tenantsSeen.map((uuid) => (
									<option key={uuid} value={uuid}>
										{nameOf(uuid)}
									</option>
								))}
							</NativeSelect.Field>
							<NativeSelect.Indicator />
						</NativeSelect.Root>
						<NativeSelect.Root size="sm" width="auto">
							<NativeSelect.Field
								aria-label="Outcome"
								value={outcome}
								onChange={(event) =>
									setOutcome(event.currentTarget.value as Outcome)
								}
							>
								<option value="all">Every outcome</option>
								<option value="succeeded">Succeeded</option>
								<option value="reverted">Reverted</option>
							</NativeSelect.Field>
							<NativeSelect.Indicator />
						</NativeSelect.Root>
						<Input
							size="sm"
							flex="1"
							minW="48"
							fontFamily="mono"
							placeholder="Account 0x…"
							aria-label="Account"
							value={account}
							onChange={(event) => setAccount(event.target.value)}
						/>
					</HStack>

					<SimpleGrid
						columns={{ base: 2, md: 4 }}
						gap="3"
						data-testid="activity-totals"
					>
						<Total label="Settlements">
							{totals.count}
							{totals.reverted > 0 && (
								<Text as="span" fontSize="sm" color="fg.muted">
									{" "}
									({totals.reverted} reverted)
								</Text>
							)}
						</Total>
						<Total label="Gas">
							<Amount wei={totals.gasWei} decimals={6} />
						</Total>
						<Total label="Fees">
							<Amount wei={totals.feeWei} decimals={6} />
						</Total>
						<Total label="Overhead">
							<Amount wei={totals.overheadWei} decimals={6} />
						</Total>
					</SimpleGrid>

					{!settlements.settled ? (
						<Text color="fg.muted">Reading the settlements…</Text>
					) : shown.length === 0 ? (
						!settlements.error && (
							<Text color="fg.muted">
								{settlements.records.length === 0
									? `Nothing settled in these blocks.${settlements.older ? " Look further back to read the window before." : ""}`
									: "No settlement matches the filters."}
							</Text>
						)
					) : (
						<Table.ScrollArea borderWidth="1px" rounded="md" maxH="36rem">
							<Table.Root size="sm" stickyHeader data-testid="activity-table">
								<Table.Header>
									<Table.Row>
										<Table.ColumnHeader>When</Table.ColumnHeader>
										<Table.ColumnHeader>Tenant</Table.ColumnHeader>
										<Table.ColumnHeader>Account</Table.ColumnHeader>
										<Table.ColumnHeader>Outcome</Table.ColumnHeader>
										<Table.ColumnHeader textAlign="end">Gas</Table.ColumnHeader>
										<Table.ColumnHeader textAlign="end">Fee</Table.ColumnHeader>
										<Table.ColumnHeader textAlign="end">
											Overhead
										</Table.ColumnHeader>
										<Table.ColumnHeader textAlign="end">
											Balance after
										</Table.ColumnHeader>
										<Table.ColumnHeader>Transaction</Table.ColumnHeader>
									</Table.Row>
								</Table.Header>
								<Table.Body>
									{shown.map((record) => {
										const time = times.get(record.blockNumber);
										const slug = names.get(record.uuid.toLowerCase());
										return (
											<Table.Row
												key={`${record.transactionHash}:${record.userOpHash}`}
											>
												<Table.Cell fontSize="xs" whiteSpace="nowrap">
													<Text>
														{time
															? new Date(time * 1000).toLocaleString()
															: "…"}
													</Text>
													<Text color="fg.muted" fontFamily="mono">
														block {record.blockNumber.toString()}
													</Text>
												</Table.Cell>
												<Table.Cell>
													{slug ? (
														<Link to={tenantPath(slug)} fontSize="sm">
															{slug}
														</Link>
													) : (
														<Copyable value={record.uuid} label="Tenant id" />
													)}
												</Table.Cell>
												<Table.Cell>
													<Copyable value={record.sender} label="Account" />
												</Table.Cell>
												<Table.Cell>
													<Badge
														colorPalette={record.success ? "green" : "orange"}
														variant="subtle"
													>
														{record.success ? "succeeded" : "reverted, charged"}
													</Badge>
												</Table.Cell>
												<Table.Cell textAlign="end">
													<Amount wei={record.gasCostWei} decimals={6} />
												</Table.Cell>
												<Table.Cell textAlign="end">
													<Amount wei={record.feeWei} decimals={6} />
												</Table.Cell>
												<Table.Cell textAlign="end">
													<Amount wei={record.overheadWei} decimals={6} />
												</Table.Cell>
												<Table.Cell textAlign="end">
													<Amount wei={record.newBalanceWei} />
												</Table.Cell>
												<Table.Cell>
													<TxLink hash={record.transactionHash} />
												</Table.Cell>
											</Table.Row>
										);
									})}
								</Table.Body>
							</Table.Root>
						</Table.ScrollArea>
					)}

					{settlements.older ? (
						<Button
							size="sm"
							variant="outline"
							alignSelf="flex-start"
							loading={settlements.loading}
							onClick={() => void settlements.lookFurther()}
						>
							<LuChevronsDown /> Look further back
						</Button>
					) : (
						settlements.settled && (
							<Text fontSize="xs" color="fg.muted">
								That reaches the first block: this is every settlement.
							</Text>
						)
					)}
				</Stack>
			</SectionCard>
			<AdminEventsCard
				client={client}
				lastUpdated={lastUpdated}
				nameOf={nameOf}
			/>
		</Stack>
	);
}

/**
 * Who changed what (B1): role changes, fees, parameters, signing keys, pause and upgrades, tenants,
 * funds, and the timelock's operations, a window of blocks at a time like the settlements.
 */
function AdminEventsCard({
	client,
	lastUpdated,
	nameOf,
}: {
	client: GianoPaymasterClient;
	lastUpdated: Date | undefined;
	nameOf: (uuid: string) => string;
}) {
	const { deployment } = useConsole();
	const events = useAdminEvents(client, lastUpdated);
	const namer = useNamer(nameOf);
	const [group, setGroup] = useState<EventGroup | "">("");
	const shown = useMemo(
		() =>
			group
				? events.items.filter((event) => eventGroup(event) === group)
				: events.items,
		[events.items, group],
	);

	return (
		<SectionCard
			title="Admin events"
			subtitle={
				events.range
					? `Who changed what on the paymaster${deployment.timelockAddress ? " and its timelock" : ""}, in blocks ${events.range.fromBlock}–${events.range.toBlock}, newest first.`
					: "Who changed what on the paymaster, newest first."
			}
			action={
				<Button
					size="sm"
					variant="ghost"
					aria-label="Read new admin events"
					loading={events.loading}
					onClick={() => void events.refresh()}
				>
					<LuRefreshCw />
				</Button>
			}
		>
			<Stack gap="3">
				{events.error && (
					<InlineError
						title="Could not read the admin events"
						error={events.error}
						retry={() => void events.refresh()}
						retrying={events.loading}
						stale={events.windows.length > 0}
					/>
				)}
				<NativeSelect.Root size="sm" width="auto" alignSelf="flex-start">
					<NativeSelect.Field
						aria-label="Kind of change"
						value={group}
						onChange={(event) =>
							setGroup(event.currentTarget.value as EventGroup | "")
						}
					>
						<option value="">Every change</option>
						{EVENT_GROUPS.map((entry) => (
							<option key={entry.group} value={entry.group}>
								{entry.label}
							</option>
						))}
					</NativeSelect.Field>
					<NativeSelect.Indicator />
				</NativeSelect.Root>
				{!events.settled ? (
					<Text color="fg.muted">Reading the admin events…</Text>
				) : shown.length === 0 ? (
					!events.error && (
						<Text color="fg.muted">
							{events.items.length === 0
								? `No admin change in these blocks.${events.older ? " Look further back to read the window before." : ""}`
								: "No change of this kind in these blocks."}
						</Text>
					)
				) : (
					<AdminEventList events={shown} namer={namer} />
				)}
				{events.older ? (
					<Button
						size="sm"
						variant="outline"
						alignSelf="flex-start"
						loading={events.loading}
						onClick={() => void events.lookFurther()}
					>
						<LuChevronsDown /> Look further back
					</Button>
				) : (
					events.settled && (
						<Text fontSize="xs" color="fg.muted">
							That reaches the first block: this is every admin event.
						</Text>
					)
				)}
			</Stack>
		</SectionCard>
	);
}

function Total({ label, children }: { label: string; children: ReactNode }) {
	return (
		<Stack gap="0.5" borderWidth="1px" rounded="md" px="3" py="2">
			<Text
				fontSize="xs"
				textTransform="uppercase"
				letterSpacing="wide"
				color="fg.muted"
			>
				{label}
			</Text>
			<Text fontFamily="mono" fontSize="lg">
				{children}
			</Text>
		</Stack>
	);
}

/** Settlements a window at a time, newest first, refreshed from the newest block read onward. */
function useSettlements(
	client: GianoPaymasterClient,
	lastUpdated: Date | undefined,
) {
	const read = useCallback(
		async (range?: Partial<BlockRange>) => {
			const page = await client.getSponsorships({ range });
			// Within a window the SDK returns settlements oldest first.
			return { ...page, items: [...page.records].reverse() };
		},
		[client],
	);
	const windows = useWindows(read, lastUpdated);
	return { ...windows, records: windows.items };
}

/** Each shown block's timestamp, read once and kept for the session. */
const blockTimeCache = new Map<string, Promise<number>>();

function useBlockTimes(
	client: GianoPaymasterClient,
	records: readonly SponsorshipRecord[],
) {
	const [times, setTimes] = useState<ReadonlyMap<bigint, number>>(new Map());
	// The newest hundred blocks shown: older rows show their block number until scrolled to by a
	// narrower filter, rather than one page asking the node for every block it ever settled in.
	const blocks = useMemo(
		() =>
			[...new Set(records.map((record) => record.blockNumber))].slice(0, 100),
		[records],
	);
	// Each block is asked for once: a read that fails is not retried in a loop, which is what keying
	// the effect on `times` did — every result made a new Map, and a block that failed was still
	// missing, so it was asked for again. A failed block shows its number without a time.
	const asked = useRef(new Set<string>());
	useEffect(() => {
		let cancelled = false;
		const missing = blocks.filter((block) => {
			const key = `${client.address}:${block}`;
			if (asked.current.has(key)) return false;
			asked.current.add(key);
			return true;
		});
		if (missing.length === 0) return;
		void Promise.all(
			missing.map(async (block) => {
				const key = `${client.address}:${block}`;
				let pending = blockTimeCache.get(key);
				if (!pending) {
					pending = client.publicClient
						.getBlock({ blockNumber: block })
						.then((header) => Number(header.timestamp));
					pending.catch(() => blockTimeCache.delete(key));
					blockTimeCache.set(key, pending);
				}
				return [block, await pending.catch(() => undefined)] as const;
			}),
		).then((entries) => {
			if (cancelled) return;
			const found = entries.filter(([, time]) => time !== undefined);
			if (found.length === 0) return;
			setTimes((current) => {
				const next = new Map(current);
				for (const [block, time] of found) next.set(block, time as number);
				return next;
			});
		});
		return () => {
			cancelled = true;
		};
	}, [client, blocks]);
	return times;
}
