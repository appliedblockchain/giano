import {
	formatDuration,
	safeTransactionBatch,
	type TenantView,
	TIMELOCK_ROLE_NAMES,
	type TimelockOperation,
	type TimelockOperationState,
	type TimelockRoleName,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Badge,
	Box,
	Button,
	DataList,
	HStack,
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
	useRef,
	useState,
} from "react";
import { LuClock, LuDownload, LuRefreshCw } from "react-icons/lu";
import { type Address, getAddress, isAddressEqual } from "viem";
import { ActionButton } from "../components/actions";
import { CallForm } from "../components/CallForm";
import {
	AddressInput,
	useAddressInput,
	useWholeNumberInput,
	WholeNumberInput,
} from "../components/inputs";
import { InlineError, QueuedMarker, StatusText } from "../components/status";
import { ExecuteButton } from "../components/timelock";
import {
	Copyable,
	notifyError,
	notifySuccess,
	SectionCard,
} from "../components/ui";
import { AddressLabel, TxLink } from "../components/values";
import { describeError } from "../lib/format";
import { downloadSafeBatch, relativeTime } from "../lib/proposals";
import { queuedKeys } from "../lib/queued";
import { useHash } from "../lib/router";
import { MAX_UINT32 } from "../lib/validate";
import { addressNames, useConsole } from "../shell/ConsoleContext";

type Filter = "pending" | "done" | "cancelled" | "all";

const STATE: Record<
	TimelockOperationState,
	{ tone: "green" | "orange" | "red" | "gray"; label: string }
> = {
	waiting: { tone: "orange", label: "waiting" },
	ready: { tone: "green", label: "ready" },
	done: { tone: "gray", label: "done" },
	cancelled: { tone: "red", label: "cancelled" },
	unset: { tone: "gray", label: "unknown" },
};

/**
 * The paymaster's timelock, operable from here (openspec N4–N6, G9): who may propose, cancel and
 * execute; the delays and the timelock's own roles, each with a proposal to change them; and its
 * operations, with Execute and Cancel for a wallet that holds the role and the Safe batch for one
 * that does not.
 */
export function TimelockTab({ tenants }: { tenants: readonly TenantView[] }) {
	const { timelock, timelockAccess, timelockOperations } = useConsole();
	// Read once for the tab: the summary and the roles card show the same holders.
	const holders = useTimelockHolders();
	if (!timelock)
		return (
			<SectionCard
				title="Timelock"
				subtitle="Upgrades, role changes, withdrawal addresses and fees wait out a public delay on a handed-off deployment"
			>
				<Text fontSize="sm" color="fg.muted">
					No timelock is configured for this deployment. Set{" "}
					<Text as="span" fontFamily="mono">
						timelockAddress
					</Text>{" "}
					on it in the console config (GIANO_TIMELOCK_ADDRESS for a
					single-deployment container) to see its delays and operations, and to
					propose and schedule changes.
				</Text>
			</SectionCard>
		);

	return (
		<Stack gap="4">
			{timelockAccess.error && (
				<InlineError
					title="Could not read the timelock"
					error={timelockAccess.error}
					retry={() => void timelockAccess.reload()}
					stale={timelockAccess.config !== undefined}
				/>
			)}
			<SummaryCard holders={holders} />
			<OperationsCard />
			<SimpleGrid columns={{ base: 1, xl: 2 }} gap="4" alignItems="start">
				<DelaysCard />
				<TimelockRolesCard holders={holders.holders} />
			</SimpleGrid>
			<ProposeCard tenants={tenants} />
			{timelockOperations.error && (
				<Text fontSize="xs" color="fg.muted">
					The operations list keeps what the last good read found.
				</Text>
			)}
		</Stack>
	);
}

/**
 * Who holds the timelock's roles among the addresses the console knows. OpenZeppelin's timelock
 * cannot enumerate its role holders, so each candidate is asked with `hasRole`.
 */
function useTimelockHolders() {
	const { timelock, deployment, wallet, paymaster } = useConsole();
	const [holders, setHolders] = useState<Record<TimelockRoleName, Address[]>>();
	const [candidates, setCandidates] = useState<Address[]>([]);
	const [error, setError] = useState<string>();

	const read = useCallback(async () => {
		if (!timelock) return;
		const unique = new Map<string, Address>();
		for (const address of [
			timelock.address,
			paymaster,
			wallet?.address,
			...Object.keys(deployment.addresses),
		])
			if (address) unique.set(address.toLowerCase(), getAddress(address));
		const list = [...unique.values()];
		try {
			const entries = await Promise.all(
				TIMELOCK_ROLE_NAMES.map(async (role) => {
					const held = await Promise.all(
						list.map((address) => timelock.hasRole(role, address)),
					);
					return [role, list.filter((_, index) => held[index])] as const;
				}),
			);
			setCandidates(list);
			setHolders(
				Object.fromEntries(entries) as Record<TimelockRoleName, Address[]>,
			);
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		}
	}, [timelock, paymaster, wallet, deployment.addresses]);

	useEffect(() => {
		void read();
	}, [read]);

	return { holders, candidates, error, read };
}

type Holders = ReturnType<typeof useTimelockHolders>;

function SummaryCard({
	holders: { holders, candidates, error, read },
}: {
	holders: Holders;
}) {
	const { timelock, timelockAccess, wallet } = useConsole();
	const { config, mayPropose, mayCancel, mayExecute } = timelockAccess;
	if (!timelock) return null;
	const roleLine = (role: TimelockRoleName, open?: boolean) =>
		open ? (
			<Text fontSize="sm">anyone (open)</Text>
		) : holders && holders[role].length > 0 ? (
			<Stack gap="1">
				{holders[role].map((holder) => (
					<AddressLabel key={holder} address={holder} label={role} />
				))}
			</Stack>
		) : (
			<Text fontSize="sm" color="fg.muted">
				{holders ? "none of the addresses checked" : "checking…"}
			</Text>
		);

	return (
		<SectionCard
			title="Timelock"
			subtitle="Every timelocked change is proposed, waits out its delay in public, then executes."
			action={
				<Button
					size="sm"
					variant="ghost"
					aria-label="Read the timelock again"
					onClick={() => void Promise.all([timelockAccess.reload(), read()])}
				>
					<LuRefreshCw />
				</Button>
			}
		>
			<Stack gap="4">
				<DataList.Root orientation="horizontal" size="sm">
					<Fact label="Address">
						<AddressLabel address={timelock.address} label="Timelock" />
					</Fact>
					<Fact label="Minimum delay">
						<HStack gap="2">
							<Text fontSize="sm">
								{config ? formatDuration(config.minDelay) : "…"}
							</Text>
							<QueuedMarker keys={queuedKeys.timelockDelay("min")} />
						</HStack>
					</Fact>
					<Fact label="Proposes">{roleLine("PROPOSER_ROLE")}</Fact>
					<Fact label="Cancels">{roleLine("CANCELLER_ROLE")}</Fact>
					<Fact label="Executes">
						{roleLine("EXECUTOR_ROLE", config?.executorsOpen)}
					</Fact>
					<Fact label="You may">
						{!wallet ? (
							<Text fontSize="sm" color="fg.muted">
								connect a wallet to act; anyone may build a proposal
							</Text>
						) : (
							<HStack gap="3" flexWrap="wrap" fontSize="sm">
								<StatusText tone={mayPropose ? "green" : "gray"}>
									{mayPropose ? "schedule" : "not schedule"}
								</StatusText>
								<StatusText tone={mayExecute ? "green" : "gray"}>
									{mayExecute === undefined
										? "execute: not read yet"
										: mayExecute
											? "execute"
											: "not execute"}
								</StatusText>
								<StatusText tone={mayCancel ? "green" : "gray"}>
									{mayCancel ? "cancel" : "not cancel"}
								</StatusText>
							</HStack>
						)}
					</Fact>
				</DataList.Root>
				{error && (
					<InlineError
						title="Could not check the timelock's roles"
						error={error}
						retry={() => void read()}
					/>
				)}
				<Text fontSize="xs" color="fg.muted">
					The timelock cannot list who holds its roles, so the console asks
					about the addresses it knows: {candidates.length} checked (the
					timelock, the paymaster, your wallet, and the deployment's configured
					addresses). Add an address to the config to have it checked.
				</Text>
			</Stack>
		</SectionCard>
	);
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="32">{label}</DataList.ItemLabel>
			<DataList.ItemValue>
				<Box minW="0">{children}</Box>
			</DataList.ItemValue>
		</DataList.Item>
	);
}

function OperationsCard() {
	const { timelockOperations } = useConsole();
	const { operations, range, hasOlder, loading, lookFurther } =
		timelockOperations;
	const [filter, setFilter] = useState<Filter>("pending");
	const shown = operations.filter((operation) =>
		filter === "all"
			? true
			: filter === "pending"
				? operation.state === "waiting" || operation.state === "ready"
				: operation.state === filter,
	);

	// A queued marker elsewhere links to /timelock#<id>: bring that operation into view, whatever the
	// filter — once per link followed. Every poll brings a new list, and re-applying the link on each
	// one would undo whatever the operator filtered or scrolled to since.
	const hash = useHash();
	const followed = useRef<string>(undefined);
	useEffect(() => {
		const id = hash.slice(1);
		if (!id || followed.current === hash) return;
		if (!operations.some((operation) => operation.id === id)) return;
		followed.current = hash;
		setFilter("all");
		requestAnimationFrame(() =>
			document.getElementById(id)?.scrollIntoView({ block: "start" }),
		);
	}, [hash, operations]);

	return (
		<SectionCard
			title={`Operations (${timelockOperations.pending.length} pending)`}
			subtitle={
				range
					? `Read from blocks ${range.fromBlock}–${range.toBlock}, newest first. Each refresh reads only the new blocks.`
					: "Read from the timelock's logs."
			}
			action={
				<HStack gap="2">
					<NativeSelect.Root size="sm" width="auto">
						<NativeSelect.Field
							aria-label="Show operations"
							value={filter}
							onChange={(event) =>
								setFilter(event.currentTarget.value as Filter)
							}
						>
							<option value="pending">Pending</option>
							<option value="done">Done</option>
							<option value="cancelled">Cancelled</option>
							<option value="all">All</option>
						</NativeSelect.Field>
						<NativeSelect.Indicator />
					</NativeSelect.Root>
					{hasOlder && (
						<Button
							size="sm"
							variant="outline"
							loading={loading}
							onClick={() => void lookFurther()}
						>
							Look further back
						</Button>
					)}
				</HStack>
			}
		>
			{timelockOperations.error && (
				<Box mb="3">
					<InlineError
						title="Could not read the timelock's operations"
						error={timelockOperations.error}
						retry={() => void timelockOperations.reload()}
						retrying={loading}
						stale={operations.length > 0}
					/>
				</Box>
			)}
			{shown.length === 0 ? (
				<Text fontSize="sm" color="fg.muted">
					{!timelockOperations.settled
						? "Reading the timelock's logs…"
						: filter === "pending"
							? "Nothing pending in these blocks."
							: "Nothing in these blocks."}
				</Text>
			) : (
				<Stack gap="3" data-testid="timelock-operations">
					{shown.map((operation) => (
						<OperationRow key={operation.id} operation={operation} />
					))}
				</Stack>
			)}
		</SectionCard>
	);
}

/** Who scheduled an operation and when: its scheduling transaction's sender and its block's time. */
const scheduledCache = new Map<string, Promise<{ by: Address; at: number }>>();

function useScheduled(operation: TimelockOperation) {
	const { timelock } = useConsole();
	const [scheduled, setScheduled] = useState<{ by: Address; at: number }>();
	const hash = operation.scheduledTransaction;
	const block = operation.scheduledBlock;
	useEffect(() => {
		if (!timelock || !hash || block === undefined) return;
		let cancelled = false;
		let pending = scheduledCache.get(hash);
		if (!pending) {
			const client = timelock.publicClient;
			pending = Promise.all([
				client.getTransaction({ hash }),
				client.getBlock({ blockNumber: block }),
			]).then(([transaction, header]) => ({
				by: transaction.from,
				at: Number(header.timestamp),
			}));
			pending.catch(() => scheduledCache.delete(hash));
			scheduledCache.set(hash, pending);
		}
		pending
			.then((value) => !cancelled && setScheduled(value))
			.catch(() => undefined);
		return () => {
			cancelled = true;
		};
	}, [timelock, hash, block]);
	return scheduled;
}

function OperationRow({ operation }: { operation: TimelockOperation }) {
	const context = useConsole();
	const { timelock, timelockAccess, deployment } = context;
	const scheduled = useScheduled(operation);
	if (!timelock) return null;
	const state = STATE[operation.state];
	const pending = operation.state === "waiting" || operation.state === "ready";
	const executorsOpen = timelockAccess.config?.executorsOpen ?? false;

	const saveBatch = (step: "execute" | "cancel") => {
		try {
			const batch = operation.complete
				? safeTransactionBatch(timelock.toProposal(operation), {
						chainId: deployment.chainId,
						step,
						description: `${step === "execute" ? "Execute" : "Cancel"} on timelock ${timelock.address}: ${summary(operation)}`,
					})
				: {
						version: "1.0" as const,
						chainId: String(deployment.chainId),
						createdAt: Date.now(),
						meta: {
							name: `Giano timelock cancel ${operation.id.slice(0, 10)}`,
							description: `Cancel on timelock ${timelock.address}: operation ${operation.id}`,
						},
						transactions: [
							{
								to: timelock.address,
								value: "0",
								data: timelock.cancelCalldata(operation.id),
							},
						],
					};
			const name = downloadSafeBatch(batch, step, operation.id);
			notifySuccess(`Saved the Safe ${step} batch`, name);
		} catch (cause) {
			notifyError(`Could not save the Safe ${step} batch`, cause);
		}
	};

	return (
		<Box
			id={operation.id}
			borderWidth="1px"
			rounded="lg"
			p="4"
			scrollMarginTop="8rem"
			data-testid={`operation-${operation.id}`}
		>
			<Stack gap="3">
				<HStack
					justify="space-between"
					align="flex-start"
					gap="3"
					flexWrap="wrap"
				>
					<Stack gap="1" minW="0">
						{operation.calls.map((call, index) => (
							<Text
								// biome-ignore lint/suspicious/noArrayIndexKey: a call's position is its identity in a batch
								key={index}
								fontSize="sm"
								fontWeight="medium"
							>
								{call.decoded?.summary ??
									`call ${call.target} with ${call.data.slice(0, 10)}…`}
							</Text>
						))}
					</Stack>
					<StatusText tone={state.tone}>{state.label}</StatusText>
				</HStack>
				<DataList.Root orientation="horizontal" size="sm">
					<Fact label="Id">
						<Copyable value={operation.id} label="Operation id" />
					</Fact>
					<Fact label="Scheduled">
						{operation.scheduledTransaction ? (
							<Stack gap="1">
								<Text fontSize="sm">
									{scheduled
										? `by ${addressNames(scheduled.by, context)[0] ?? scheduled.by} at ${new Date(scheduled.at * 1000).toLocaleString()}`
										: `in block ${operation.scheduledBlock}`}
								</Text>
								{scheduled && !addressNames(scheduled.by, context).length && (
									<Copyable value={scheduled.by} label="Scheduled by" />
								)}
								<TxLink hash={operation.scheduledTransaction} />
							</Stack>
						) : (
							<Text fontSize="sm" color="fg.muted">
								before the blocks read
							</Text>
						)}
					</Fact>
					{operation.delay !== undefined && (
						<Fact label="Delay">{formatDuration(operation.delay)}</Fact>
					)}
					{operation.readyAt !== undefined && pending && (
						<Fact label="Ready">
							{operation.state === "ready"
								? "now"
								: operation.readyAt * 1000 <= Date.now()
									? `due since ${new Date(operation.readyAt * 1000).toLocaleString()}: executable from the chain's next block`
									: `${new Date(operation.readyAt * 1000).toLocaleString()} (${relativeTime(operation.readyAt)})`}
						</Fact>
					)}
					{operation.complete && (
						<>
							<Fact label="Salt">
								<Copyable value={operation.salt} label="Salt" />
							</Fact>
							<Fact label="Predecessor">
								{/^0x0+$/.test(operation.predecessor) ? (
									"none"
								) : (
									<Copyable value={operation.predecessor} label="Predecessor" />
								)}
							</Fact>
						</>
					)}
					{operation.executedTransaction && (
						<Fact label="Executed">
							<TxLink hash={operation.executedTransaction} />
						</Fact>
					)}
					{operation.cancelledTransaction && (
						<Fact label="Cancelled">
							<TxLink hash={operation.cancelledTransaction} />
						</Fact>
					)}
				</DataList.Root>
				{!operation.complete && (
					<Text fontSize="xs" color="fg.muted">
						Scheduled before the blocks read: its calls, salt and predecessor
						are not known here, so it cannot be executed from this console. Look
						further back to find its scheduling.
					</Text>
				)}
				{pending && (
					<HStack gap="2" flexWrap="wrap">
						<ExecuteButton
							operationId={operation.id}
							mayExecute={timelockAccess.mayExecute}
							size="sm"
						/>
						<ActionButton
							target={{
								gate: {
									allowed: timelockAccess.mayCancel,
									reason:
										"Needs the timelock's CANCELLER_ROLE: hand the cancel batch to the canceller.",
								},
							}}
							label="Cancel"
							destructive
							send={() => timelock.cancel(operation.id)}
							confirm={{
								title: "Cancel the timelock operation",
								effect: `${summary(operation)}. It will never execute; proposing it again starts a new delay.`,
								confirmLabel: "Cancel operation",
							}}
						/>
						{operation.state === "ready" &&
							operation.complete &&
							!executorsOpen && (
								<Button
									size="sm"
									variant="outline"
									onClick={() => saveBatch("execute")}
								>
									<LuDownload /> Safe batch (execute)
								</Button>
							)}
						<Button
							size="sm"
							variant="outline"
							onClick={() => saveBatch("cancel")}
						>
							<LuDownload /> Safe batch (cancel)
						</Button>
					</HStack>
				)}
			</Stack>
		</Box>
	);
}

function summary(operation: TimelockOperation): string {
	const text = operation.calls
		.map(
			(call) =>
				call.decoded?.summary ??
				`call ${call.target} with ${call.data.slice(0, 10)}…`,
		)
		.join("; ");
	return `${text.charAt(0).toUpperCase()}${text.slice(1)}`;
}

function DelaysCard() {
	const { timelockAccess, propose } = useConsole();
	const { config } = timelockAccess;
	return (
		<SectionCard
			title="Delays"
			subtitle="Each timelocked function waits its own delay, never less than the minimum. Changing a delay is itself timelocked."
		>
			{!config ? (
				<Text fontSize="sm" color="fg.muted">
					Reading the delays…
				</Text>
			) : (
				<Table.ScrollArea borderWidth="1px" rounded="md">
					<Table.Root size="sm">
						<Table.Header>
							<Table.Row>
								<Table.ColumnHeader>Function</Table.ColumnHeader>
								<Table.ColumnHeader textAlign="end">Delay</Table.ColumnHeader>
								<Table.ColumnHeader>Change</Table.ColumnHeader>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							<Table.Row>
								<Table.Cell>
									<Text fontSize="sm" fontWeight="medium">
										Minimum
									</Text>
									<Text fontSize="xs" color="fg.muted">
										every operation, and any function without its own
									</Text>
								</Table.Cell>
								<Table.Cell textAlign="end" fontFamily="mono" fontSize="sm">
									{formatDuration(config.minDelay)}
								</Table.Cell>
								<Table.Cell>
									<ChangeDelay
										current={config.minDelay}
										onPropose={(seconds) =>
											propose?.({ kind: "updateDelay", seconds })
										}
									/>
								</Table.Cell>
							</Table.Row>
							{config.functions.map((entry) => (
								<Table.Row key={entry.functionName}>
									<Table.Cell>
										<Text fontSize="sm" fontFamily="mono">
											{entry.functionName}
										</Text>
										<HStack gap="1" flexWrap="wrap">
											<Text fontSize="xs" color="fg.muted">
												{entry.role}
											</Text>
											{!config.holdsRole[entry.role] && (
												<Badge
													colorPalette="orange"
													size="sm"
													variant="outline"
												>
													not held by the timelock
												</Badge>
											)}
										</HStack>
										<QueuedMarker
											keys={queuedKeys.timelockDelay(entry.selector)}
										/>
									</Table.Cell>
									<Table.Cell textAlign="end" fontFamily="mono" fontSize="sm">
										{formatDuration(entry.effectiveDelay)}
										{entry.functionDelay === 0n && (
											<Text fontSize="xs" color="fg.muted">
												the minimum
											</Text>
										)}
									</Table.Cell>
									<Table.Cell>
										<ChangeDelay
											current={entry.functionDelay}
											onPropose={(seconds) =>
												propose?.({
													kind: "setFunctionDelay",
													functionName: entry.functionName,
													selector: entry.selector,
													seconds,
												})
											}
										/>
									</Table.Cell>
								</Table.Row>
							))}
						</Table.Body>
					</Table.Root>
				</Table.ScrollArea>
			)}
		</SectionCard>
	);
}

/** A new delay in seconds and a Propose control: changing a delay is always a timelock operation. */
function ChangeDelay({
	current,
	onPropose,
}: {
	current: bigint;
	onPropose: (seconds: bigint) => void;
}) {
	const [open, setOpen] = useState(false);
	const seconds = useWholeNumberInput({ max: MAX_UINT32, unit: "seconds" });
	const value = seconds.value;
	if (!open)
		return (
			<Button
				size="xs"
				variant="ghost"
				colorPalette="timelock"
				onClick={() => setOpen(true)}
			>
				<LuClock /> Change
			</Button>
		);
	return (
		<Stack gap="2" minW="48">
			<WholeNumberInput
				input={seconds}
				label="New delay"
				unit="s"
				helper={
					value !== undefined
						? formatDuration(value)
						: `now ${formatDuration(current)}`
				}
			/>
			<HStack gap="2">
				<Button
					size="xs"
					variant="outline"
					colorPalette="timelock"
					disabled={value === undefined || value === current}
					onClick={() => value !== undefined && onPropose(value)}
				>
					<LuClock /> Propose
				</Button>
				<Button size="xs" variant="ghost" onClick={() => setOpen(false)}>
					Close
				</Button>
			</HStack>
		</Stack>
	);
}

function TimelockRolesCard({ holders }: { holders: Holders["holders"] }) {
	const { propose } = useConsole();
	const [role, setRole] = useState<TimelockRoleName>("PROPOSER_ROLE");
	const account = useAddressInput();
	const grantee = account.value;
	return (
		<SectionCard
			title="The timelock's own roles"
			subtitle="Who may propose, cancel and execute. Changing them is a timelock operation, executed by the timelock itself."
		>
			<Stack gap="4">
				{TIMELOCK_ROLE_NAMES.map((name) => (
					<Stack key={name} gap="1">
						<HStack gap="2">
							<Text fontSize="sm" fontFamily="mono" fontWeight="medium">
								{name}
							</Text>
							<QueuedMarker keys={queuedKeys.timelockRole(name)} />
						</HStack>
						{holders?.[name].length ? (
							holders[name].map((holder) => (
								<HStack key={holder} gap="2" flexWrap="wrap">
									<AddressLabel address={holder} label={name} />
									<Button
										size="xs"
										variant="ghost"
										colorPalette="timelock"
										onClick={() =>
											propose?.({
												kind: "revokeTimelockRole",
												role: name,
												account: holder,
											})
										}
									>
										<LuClock /> Propose revoke
									</Button>
								</HStack>
							))
						) : (
							<Text fontSize="xs" color="fg.muted">
								{holders ? "none of the addresses checked" : "checking…"}
							</Text>
						)}
					</Stack>
				))}
				<Stack gap="2" borderTopWidth="1px" pt="3">
					<NativeSelect.Root size="sm" width="auto" maxW="xs">
						<NativeSelect.Field
							aria-label="Timelock role"
							value={role}
							onChange={(event) =>
								setRole(event.currentTarget.value as TimelockRoleName)
							}
						>
							{TIMELOCK_ROLE_NAMES.map((name) => (
								<option key={name} value={name}>
									{name}
								</option>
							))}
						</NativeSelect.Field>
						<NativeSelect.Indicator />
					</NativeSelect.Root>
					<AddressInput input={account} label="Grant to" />
					<Box>
						<Button
							size="sm"
							variant="outline"
							colorPalette="timelock"
							disabled={
								!grantee ||
								(holders?.[role] ?? []).some(
									(holder) => grantee && isAddressEqual(holder, grantee),
								)
							}
							onClick={() =>
								grantee &&
								propose?.({ kind: "grantTimelockRole", role, account: grantee })
							}
						>
							<LuClock /> Propose grant
						</Button>
					</Box>
				</Stack>
			</Stack>
		</SectionCard>
	);
}

function ProposeCard({ tenants }: { tenants: readonly TenantView[] }) {
	const { propose } = useConsole();
	if (!propose) return null;
	return (
		<SectionCard
			title="Propose a change"
			subtitle="Builds the proposal: add more calls to it in the dialog, set its salt, delay and predecessor, and schedule it or save the Safe batch."
		>
			<CallForm
				tenants={tenants}
				actionLabel="Build proposal"
				onAdd={propose}
			/>
		</SectionCard>
	);
}
