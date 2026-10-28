import {
	formatDuration,
	type GianoTimelockClient,
	PAYMASTER_ROLE_NAMES,
	type PaymasterRoleName,
	safeTransactionBatch,
	type TenantView,
	type TimelockConfig,
	type TimelockOperation,
	type TimelockOperationState,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Badge,
	Box,
	Button,
	Field,
	HStack,
	Input,
	NativeSelect,
	SimpleGrid,
	Spinner,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";
import { LuDownload, LuPlay, LuRefreshCw } from "react-icons/lu";
import { type Address, type Hex, isAddress, parseEther } from "viem";
import {
	Copyable,
	notifyError,
	notifySuccess,
	SectionCard,
	Stat,
} from "../components/ui";
import { useWrite } from "../hooks/useWrite";
import { describeError } from "../lib/format";
import {
	downloadSafeBatch,
	type ProposalRequest,
	type Propose,
	relativeTime,
} from "../lib/proposals";

type Props = {
	/** Undefined when this deployment has no `timelockAddress` configured. */
	timelock: GianoTimelockClient | undefined;
	tenants: readonly TenantView[];
	connected: boolean;
	propose: Propose | undefined;
	/** The console's paymaster refresh: an executed operation changes what the other tabs show. */
	refresh: () => Promise<void>;
	/** Bumped by every console refresh, so this tab re-reads alongside the rest. */
	lastUpdated: Date | undefined;
};

/** Blocks read per window, as everywhere else; the first read goes this many windows back. */
const INITIAL_WINDOWS = 5;

const STATE_TONE: Record<
	TimelockOperationState,
	{ colorPalette: string; label: string }
> = {
	waiting: { colorPalette: "orange", label: "waiting" },
	ready: { colorPalette: "green", label: "ready" },
	done: { colorPalette: "gray", label: "done" },
	cancelled: { colorPalette: "red", label: "cancelled" },
	unset: { colorPalette: "gray", label: "unknown" },
};

/**
 * The paymaster's timelock (G9): its delays, what is queued in it, and the proposal builder.
 *
 * Read-only by design except for one button. Upgrades, role changes, withdrawal addresses and fees
 * go through the timelock on a handed-off deployment, and its proposer is a Safe (R3), so this tab
 * builds proposals for the Safe to sign rather than sending them (R5). The exception is Execute: a
 * ready operation on a timelock whose executors are open may be executed by anyone — the delay is
 * the protection, not who presses the button — so the connected wallet can do it.
 *
 * Operations come from the timelock's logs, a window of blocks at a time like every other log read
 * here. The first read goes {@link INITIAL_WINDOWS} windows back and "Look further back" extends
 * it; an operation scheduled before the blocks read is listed only once something later happens to
 * it, and is marked as such.
 */
export function TimelockPanel({
	timelock,
	tenants,
	connected,
	propose,
	refresh,
	lastUpdated,
}: Props) {
	const [config, setConfig] = useState<TimelockConfig>();
	const [operations, setOperations] = useState<readonly TimelockOperation[]>(
		[],
	);
	const [range, setRange] = useState<{ fromBlock: bigint; toBlock: bigint }>();
	const [windows, setWindows] = useState(INITIAL_WINDOWS);
	const [hasOlder, setHasOlder] = useState(false);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();

	const load = useCallback(async () => {
		if (!timelock) return;
		setLoading(true);
		try {
			const [nextConfig, page] = await Promise.all([
				timelock.getConfig(),
				timelock.getOperations({ windows }),
			]);
			setConfig(nextConfig);
			setOperations(page.operations);
			setRange({ fromBlock: page.fromBlock, toBlock: page.toBlock });
			setHasOlder(page.older !== undefined);
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
			console.error("[paymaster-admin] Could not read the timelock", cause);
		} finally {
			setLoading(false);
		}
	}, [timelock, windows]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: every console refresh re-reads the timelock too
	useEffect(() => {
		void load();
	}, [load, lastUpdated]);

	const { run, busy, isPending } = useWrite(async () => {
		await Promise.all([load(), refresh()]);
	});

	if (!timelock) {
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
					single-deployment container) to see its delays and pending operations,
					and to build proposals for it.
				</Text>
			</SectionCard>
		);
	}

	const saveBatch = (
		operation: TimelockOperation,
		step: "execute" | "cancel",
	) => {
		if (!config) return;
		try {
			const proposal = timelock.toProposal(operation);
			const name = downloadSafeBatch(
				safeTransactionBatch(proposal, {
					chainId: config.chainId,
					step,
					description: `${step === "execute" ? "Execute" : "Cancel"} on timelock ${timelock.address}: ${summary(operation)}`,
				}),
				step,
				operation.id,
			);
			notifySuccess(`Saved the Safe ${step} batch`, name);
		} catch (cause) {
			notifyError(`Could not save the Safe ${step} batch`, cause);
		}
	};

	const pending = operations.filter(
		(operation) => operation.state === "waiting" || operation.state === "ready",
	);

	return (
		<Stack gap="4">
			{error && (
				<Alert.Root status="error">
					<Alert.Indicator />
					<Alert.Content>
						<Alert.Title>Could not read the timelock</Alert.Title>
						<Alert.Description>{error}</Alert.Description>
					</Alert.Content>
				</Alert.Root>
			)}

			<SectionCard
				title="Timelock"
				subtitle="Each timelocked paymaster function waits its own delay, never less than the minimum. Changing a delay is itself timelocked."
				action={
					<Button
						size="sm"
						variant="ghost"
						onClick={() => void load()}
						loading={loading}
						aria-label="Refresh the timelock"
					>
						<LuRefreshCw />
					</Button>
				}
			>
				{!config ? (
					<HStack gap="3">
						<Spinner size="sm" color="brand.solid" />
						<Text fontSize="sm" color="fg.muted">
							Reading the timelock…
						</Text>
					</HStack>
				) : (
					<Stack gap="4">
						<SimpleGrid columns={{ base: 1, md: 3 }} gap="4">
							<Box>
								<Text
									fontSize="xs"
									textTransform="uppercase"
									letterSpacing="wide"
									color="fg.muted"
								>
									Address
								</Text>
								<Copyable value={config.address} label="Timelock" />
							</Box>
							<Stat
								label="Minimum delay"
								value={formatDuration(config.minDelay)}
							/>
							<Stat
								label="Executors"
								value={config.executorsOpen ? "open" : "restricted"}
								hint={
									config.executorsOpen
										? "anyone may execute a ready operation"
										: "only EXECUTOR_ROLE holders — send the execute batch from them"
								}
							/>
						</SimpleGrid>

						<Table.ScrollArea borderWidth="1px" rounded="md">
							<Table.Root size="sm">
								<Table.Header>
									<Table.Row>
										<Table.ColumnHeader>Function</Table.ColumnHeader>
										<Table.ColumnHeader>Role</Table.ColumnHeader>
										<Table.ColumnHeader textAlign="end">
											Delay
										</Table.ColumnHeader>
										<Table.ColumnHeader>Why it waits</Table.ColumnHeader>
									</Table.Row>
								</Table.Header>
								<Table.Body>
									{config.functions.map((entry) => (
										<Table.Row key={entry.functionName}>
											<Table.Cell fontFamily="mono" fontSize="xs">
												{entry.functionName}
											</Table.Cell>
											<Table.Cell>
												<HStack gap="2">
													<Text fontSize="sm">{entry.role}</Text>
													{!config.holdsRole[entry.role] && (
														<Badge colorPalette="orange" size="sm">
															not held by the timelock
														</Badge>
													)}
												</HStack>
											</Table.Cell>
											<Table.Cell
												textAlign="end"
												fontFamily="mono"
												title={
													entry.functionDelay === 0n
														? "no delay of its own: the minimum"
														: `its own delay: ${formatDuration(entry.functionDelay)}`
												}
											>
												{formatDuration(entry.effectiveDelay)}
											</Table.Cell>
											<Table.Cell fontSize="sm" color="fg.muted">
												{entry.why}
											</Table.Cell>
										</Table.Row>
									))}
								</Table.Body>
							</Table.Root>
						</Table.ScrollArea>

						{Object.values(config.holdsRole).some((held) => !held) && (
							<Text fontSize="xs" color="orange.fg">
								The timelock does not hold every timelocked role yet, so the
								functions marked above are still sent from whichever key holds
								them. The deploy CLI's handoff moves them.
							</Text>
						)}
					</Stack>
				)}
			</SectionCard>

			<SectionCard
				title={`Operations (${pending.length} pending)`}
				subtitle={
					range
						? `Scheduled, executed or cancelled in blocks ${range.fromBlock}–${range.toBlock}, newest first`
						: "Read from the timelock's logs"
				}
				action={
					hasOlder && (
						<Button
							size="sm"
							variant="outline"
							disabled={loading}
							onClick={() => setWindows((current) => current * 2)}
						>
							Look further back
						</Button>
					)
				}
			>
				{operations.length === 0 ? (
					<Text fontSize="sm" color="fg.muted">
						{config
							? "Nothing scheduled in these blocks."
							: "Reading the timelock's logs…"}
					</Text>
				) : (
					<Table.ScrollArea borderWidth="1px" rounded="md">
						<Table.Root size="sm">
							<Table.Header>
								<Table.Row>
									<Table.ColumnHeader>Operation</Table.ColumnHeader>
									<Table.ColumnHeader>State</Table.ColumnHeader>
									<Table.ColumnHeader>ETA</Table.ColumnHeader>
									<Table.ColumnHeader textAlign="end">
										Actions
									</Table.ColumnHeader>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{operations.map((operation) => {
									const tone = STATE_TONE[operation.state];
									const label = `Execute ${operation.id.slice(0, 10)}`;
									const actionable =
										operation.complete &&
										(operation.state === "waiting" ||
											operation.state === "ready");
									return (
										<Table.Row key={operation.id}>
											<Table.Cell>
												<Stack gap="1">
													{operation.calls.map((call, index) => (
														<Text
															// biome-ignore lint/suspicious/noArrayIndexKey: a call's position is its identity in a batch
															key={index}
															fontSize="sm"
														>
															{call.decoded?.summary ??
																`call ${call.target} with ${call.data.slice(0, 10)}…`}
														</Text>
													))}
													<Copyable value={operation.id} label="Operation id" />
													{!operation.complete && (
														<Text fontSize="xs" color="fg.muted">
															Scheduled before the blocks read — look further
															back for its full scheduling.
														</Text>
													)}
												</Stack>
											</Table.Cell>
											<Table.Cell>
												<Badge
													colorPalette={tone.colorPalette}
													variant="subtle"
												>
													{tone.label}
												</Badge>
											</Table.Cell>
											<Table.Cell fontSize="sm">
												{operation.readyAt !== undefined ? (
													<Stack gap="0">
														<Text>
															{new Date(
																operation.readyAt * 1000,
															).toLocaleString()}
														</Text>
														<Text fontSize="xs" color="fg.muted">
															{operation.state === "ready"
																? "executable now"
																: relativeTime(operation.readyAt)}
														</Text>
													</Stack>
												) : (
													<Text color="fg.muted">
														{operation.state === "done"
															? `executed in block ${operation.executedBlock ?? "?"}`
															: operation.state === "cancelled"
																? `cancelled in block ${operation.cancelledBlock ?? "?"}`
																: "—"}
													</Text>
												)}
											</Table.Cell>
											<Table.Cell textAlign="end">
												<HStack gap="1" justify="flex-end" flexWrap="wrap">
													{operation.state === "ready" &&
														operation.complete &&
														config?.executorsOpen && (
															<Button
																size="xs"
																colorPalette="brand"
																disabled={!connected || busy}
																loading={isPending(label)}
																title={
																	connected
																		? "Executors are open: any account may execute a ready operation"
																		: "Connect a wallet to execute"
																}
																onClick={() =>
																	void run(label, () =>
																		timelock.executeOperation(operation),
																	)
																}
															>
																<LuPlay /> Execute
															</Button>
														)}
													{operation.state === "ready" &&
														operation.complete &&
														config &&
														!config.executorsOpen && (
															<Button
																size="xs"
																variant="outline"
																onClick={() => saveBatch(operation, "execute")}
															>
																<LuDownload /> Safe batch (execute)
															</Button>
														)}
													{actionable && (
														<Button
															size="xs"
															variant="ghost"
															colorPalette="red"
															onClick={() => saveBatch(operation, "cancel")}
														>
															<LuDownload /> Safe batch (cancel)
														</Button>
													)}
												</HStack>
											</Table.Cell>
										</Table.Row>
									);
								})}
							</Table.Body>
						</Table.Root>
					</Table.ScrollArea>
				)}
			</SectionCard>

			{propose && <ProposalBuilder tenants={tenants} propose={propose} />}
		</Stack>
	);
}

function summary(operation: TimelockOperation): string {
	return operation.calls
		.map(
			(call) =>
				call.decoded?.summary ??
				`call ${call.target} with ${call.data.slice(0, 10)}…`,
		)
		.join("; ");
}

type Kind =
	| "setDefaultFee"
	| "setTenantFee"
	| "clearTenantFee"
	| "setTenantWithdrawAddress"
	| "grantRole"
	| "revokeRole";

const KINDS: { kind: Kind; label: string }[] = [
	{ kind: "setDefaultFee", label: "Set the default fee" },
	{ kind: "setTenantFee", label: "Set a tenant's fee override" },
	{ kind: "clearTenantFee", label: "Clear a tenant's fee override" },
	{ kind: "setTenantWithdrawAddress", label: "Change a withdrawal address" },
	{ kind: "grantRole", label: "Grant a role" },
	{ kind: "revokeRole", label: "Revoke a role" },
];

/**
 * Builds a proposal for any timelocked action, whoever is connected — building one needs no role
 * and no wallet, only the timelock's delays. The result opens in the proposal dialog.
 */
function ProposalBuilder({
	tenants,
	propose,
}: {
	tenants: readonly TenantView[];
	propose: Propose;
}) {
	const [kind, setKind] = useState<Kind>("setDefaultFee");
	const [tenant, setTenant] = useState<string>(tenants[0]?.id ?? "");
	const [fee, setFee] = useState("");
	const [address, setAddress] = useState("");
	const [role, setRole] = useState<PaymasterRoleName>("FEE_ADMIN_ROLE");
	const [problem, setProblem] = useState<string>();

	const needsTenant =
		kind === "setTenantFee" ||
		kind === "clearTenantFee" ||
		kind === "setTenantWithdrawAddress";
	const needsFee = kind === "setDefaultFee" || kind === "setTenantFee";
	const needsAddress =
		kind === "setTenantWithdrawAddress" ||
		kind === "grantRole" ||
		kind === "revokeRole";
	const needsRole = kind === "grantRole" || kind === "revokeRole";

	const build = () => {
		const fail = (message: string) => {
			setProblem(message);
			console.error(
				`[paymaster-admin] Could not build the proposal: ${message}`,
			);
		};

		let feeWei = 0n;
		if (needsFee) {
			if (!fee.trim()) return fail("Enter a fee in ETH.");
			try {
				feeWei = parseEther(fee.trim());
			} catch {
				return fail(`"${fee}" is not an amount in ETH.`);
			}
		}
		if (needsAddress && !isAddress(address))
			return fail(`"${address}" is not an address.`);
		if (needsTenant && !tenant) return fail("Choose a tenant.");

		const tenantId = tenant as Hex;
		const account = address as Address;
		const request: ProposalRequest =
			kind === "setDefaultFee"
				? { kind, feeWei }
				: kind === "setTenantFee"
					? { kind, tenantId, hasOverride: true, feeWei }
					: kind === "clearTenantFee"
						? { kind: "setTenantFee", tenantId, hasOverride: false, feeWei: 0n }
						: kind === "setTenantWithdrawAddress"
							? { kind, tenantId, withdrawAddress: account }
							: { kind, role, account };
		setProblem(undefined);
		propose(request);
	};

	return (
		<SectionCard
			title="Propose a change"
			subtitle="Builds the timelock proposal and the Safe Transaction Builder batch. Nothing is sent from here."
		>
			<Stack gap="3">
				<HStack gap="3" flexWrap="wrap" align="flex-end">
					<Field.Root width="auto" minW="16rem">
						<Field.Label fontSize="sm">Change</Field.Label>
						<NativeSelect.Root size="sm">
							<NativeSelect.Field
								value={kind}
								onChange={(event) => setKind(event.currentTarget.value as Kind)}
							>
								{KINDS.map((entry) => (
									<option key={entry.kind} value={entry.kind}>
										{entry.label}
									</option>
								))}
							</NativeSelect.Field>
							<NativeSelect.Indicator />
						</NativeSelect.Root>
					</Field.Root>

					{needsTenant && (
						<Field.Root width="auto" minW="22rem">
							<Field.Label fontSize="sm">Tenant</Field.Label>
							<NativeSelect.Root size="sm">
								<NativeSelect.Field
									value={tenant}
									onChange={(event) => setTenant(event.currentTarget.value)}
								>
									{tenants.map((entry) => (
										<option key={entry.id} value={entry.id}>
											{entry.uuid}
										</option>
									))}
								</NativeSelect.Field>
								<NativeSelect.Indicator />
							</NativeSelect.Root>
						</Field.Root>
					)}

					{needsRole && (
						<Field.Root width="auto" minW="16rem">
							<Field.Label fontSize="sm">Role</Field.Label>
							<NativeSelect.Root size="sm">
								<NativeSelect.Field
									value={role}
									onChange={(event) =>
										setRole(event.currentTarget.value as PaymasterRoleName)
									}
								>
									{PAYMASTER_ROLE_NAMES.map((name) => (
										<option key={name} value={name}>
											{name}
										</option>
									))}
								</NativeSelect.Field>
								<NativeSelect.Indicator />
							</NativeSelect.Root>
						</Field.Root>
					)}

					{needsFee && (
						<Field.Root width="auto" minW="10rem">
							<Field.Label fontSize="sm">Fee (ETH)</Field.Label>
							<Input
								size="sm"
								value={fee}
								onChange={(event) => setFee(event.target.value)}
								placeholder="0.0001"
								inputMode="decimal"
							/>
						</Field.Root>
					)}

					{needsAddress && (
						<Field.Root flex="1" minW="20rem">
							<Field.Label fontSize="sm">
								{kind === "setTenantWithdrawAddress"
									? "New withdrawal address"
									: "Account"}
							</Field.Label>
							<Input
								size="sm"
								value={address}
								onChange={(event) => setAddress(event.target.value)}
								placeholder="0x…"
							/>
						</Field.Root>
					)}

					<Button size="sm" colorPalette="brand" onClick={build}>
						Build proposal
					</Button>
				</HStack>
				{problem && (
					<Text fontSize="sm" color="red.fg">
						{problem}
					</Text>
				)}
				{needsTenant && tenants.length === 0 && (
					<Text fontSize="sm" color="fg.muted">
						No tenants are registered on this paymaster.
					</Text>
				)}
			</Stack>
		</SectionCard>
	);
}
