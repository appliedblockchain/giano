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
import { InlineError } from "../components/status";
import {
	Copyable,
	notifyError,
	notifySuccess,
	SectionCard,
} from "../components/ui";
import { Amount, TxLink } from "../components/values";
import {
	filterSettlements,
	type Outcome,
	settlementsCsv,
	settlementTotals,
} from "../lib/activity";
import { describeError } from "../lib/format";
import { Link, tenantPath } from "../lib/router";
import type { TenantRow } from "../lib/tenants";
import { useConsole } from "../shell/ConsoleContext";

type Window = BlockRange & { records: readonly SponsorshipRecord[] };

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
													{time ? new Date(time * 1000).toLocaleString() : "…"}
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
	const [windows, setWindows] = useState<readonly Window[]>([]);
	const [older, setOlder] = useState<BlockRange>();
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();
	const [settled, setSettled] = useState(false);
	const newest = useRef<bigint | undefined>(undefined);
	const running = useRef(false);

	const refresh = useCallback(async () => {
		if (running.current) return;
		running.current = true;
		setLoading(true);
		try {
			const from = newest.current;
			const page = await client.getSponsorships(
				from === undefined ? {} : { range: { fromBlock: from + 1n } },
			);
			const window = {
				fromBlock: page.fromBlock,
				toBlock: page.toBlock,
				records: page.records,
			};
			if (from === undefined) {
				setWindows([window]);
				setOlder(page.older);
			} else if (page.toBlock > from) {
				setWindows((current) => [window, ...current]);
			}
			if (from === undefined || page.toBlock > from)
				newest.current = page.toBlock;
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		} finally {
			running.current = false;
			setLoading(false);
			setSettled(true);
		}
	}, [client]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: read the new blocks with every console refresh
	useEffect(() => {
		void refresh();
	}, [refresh, lastUpdated]);

	const lookFurther = useCallback(async () => {
		if (!older) return;
		setLoading(true);
		try {
			const page = await client.getSponsorships({ range: older });
			setWindows((current) => [
				...current,
				{
					fromBlock: page.fromBlock,
					toBlock: page.toBlock,
					records: page.records,
				},
			]);
			setOlder(page.older);
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		} finally {
			setLoading(false);
		}
	}, [client, older]);

	// Within a window the SDK returns settlements oldest first.
	const records = useMemo(
		() => windows.flatMap((window) => [...window.records].reverse()),
		[windows],
	);
	const range =
		windows.length > 0
			? {
					fromBlock: windows[windows.length - 1].fromBlock,
					toBlock: windows[0].toBlock,
				}
			: undefined;

	return {
		windows,
		records,
		range,
		older,
		loading,
		error,
		settled,
		refresh,
		lookFurther,
	};
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
	useEffect(() => {
		let cancelled = false;
		const missing = blocks.filter((block) => !times.has(block));
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
			setTimes((current) => {
				const next = new Map(current);
				for (const [block, time] of entries)
					if (time !== undefined) next.set(block, time);
				return next;
			});
		});
		return () => {
			cancelled = true;
		};
	}, [client, blocks, times]);
	return times;
}
