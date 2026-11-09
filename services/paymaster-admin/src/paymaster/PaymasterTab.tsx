import {
	formatDuration,
	type GianoPaymasterClient,
	isTimelockedRole,
	type PaymasterOverview,
	type PaymasterRoleName,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Badge,
	Box,
	DataList,
	HStack,
	SimpleGrid,
	Stack,
	Text,
} from "@chakra-ui/react";
import {
	type ReactNode,
	useCallback,
	useEffect,
	useRef,
	useState,
} from "react";
import { LuPause, LuPlay, LuTrash2 } from "react-icons/lu";
import type { Address } from "viem";
import { ActionButton } from "../components/actions";
import {
	AddressInput,
	AmountInput,
	CalldataInput,
	useAddressInput,
	useAmountInput,
	useCalldataInput,
	useInput,
	useWholeNumberInput,
	WholeNumberInput,
} from "../components/inputs";
import {
	InlineError,
	QueuedMarker,
	StatusText,
	TimelockedTag,
} from "../components/status";
import { SectionCard } from "../components/ui";
import { AddressLabel, Amount } from "../components/values";
import { describeError } from "../lib/format";
import { queuedKeys } from "../lib/queued";
import { MAX_UINT32, parsePenaltyBps } from "../lib/validate";
import { useConsole } from "../shell/ConsoleContext";
import { useNow } from "../shell/Header";

/**
 * Every paymaster setting, one card per area (openspec K4): each names the role it needs, whether
 * that role is timelocked, and whether the connected wallet holds it. Every write goes through the
 * shared write rules, so a control the wallet cannot use is shown disabled with the reason rather
 * than hidden.
 */
export function PaymasterTab({
	client,
	overview,
}: {
	client: GianoPaymasterClient;
	overview: PaymasterOverview;
}) {
	return (
		<Stack gap="4">
			<PauseCard client={client} paused={overview.config.paused} />
			<SimpleGrid columns={{ base: 1, lg: 2 }} gap="4" alignItems="start">
				<SignersCard client={client} signers={overview.signers} />
				<PricingCard
					client={client}
					defaultFeeWei={overview.config.defaultFeeWei}
				/>
				<ParametersCard
					client={client}
					postOpGasAllowance={overview.config.postOpGasAllowance}
					penaltyBps={overview.config.penaltyBps}
				/>
				<TreasuryCard
					client={client}
					treasuryWei={overview.solvency.treasuryWei}
				/>
				<StakeCard client={client} stake={overview.stake} />
				<UpgradeCard client={client} />
			</SimpleGrid>
		</Stack>
	);
}

/** Which role a card needs, whether it waits out the timelock, and whether this wallet holds it. */
function RoleLine({ role }: { role: PaymasterRoleName }) {
	const { myRoles, wallet } = useConsole();
	const held = myRoles.includes(role);
	return (
		<HStack gap="2" flexWrap="wrap" fontSize="xs" color="fg.muted">
			<Badge variant="outline" fontFamily="mono">
				{role}
			</Badge>
			{isTimelockedRole(role) ? (
				<TimelockedTag />
			) : (
				<Badge variant="subtle">immediate</Badge>
			)}
			<Text as="span">
				{!wallet
					? "no wallet connected"
					: held
						? "you hold it"
						: "you do not hold it"}
			</Text>
		</HStack>
	);
}

function Card({
	title,
	subtitle,
	needs,
	children,
}: {
	title: string;
	subtitle: string;
	/** The role the card's writes need. */
	needs: PaymasterRoleName;
	children: ReactNode;
}) {
	return (
		<SectionCard title={title} subtitle={subtitle}>
			<Stack gap="4">
				<RoleLine role={needs} />
				{children}
			</Stack>
		</SectionCard>
	);
}

function Facts({ children }: { children: ReactNode }) {
	return (
		<DataList.Root orientation="horizontal" size="sm">
			{children}
		</DataList.Root>
	);
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="36">{label}</DataList.ItemLabel>
			<DataList.ItemValue>
				{/* Lets a long address wrap at phone width instead of overflowing. */}
				<Box minW="0">{children}</Box>
			</DataList.ItemValue>
		</DataList.Item>
	);
}

function PauseCard({
	client,
	paused,
}: {
	client: GianoPaymasterClient;
	paused: boolean;
}) {
	return (
		<Card
			title="Pause"
			subtitle="Stops new sponsorships and nothing else: tenant withdrawals keep working while paused."
			needs="PAUSER_ROLE"
		>
			<HStack gap="4" flexWrap="wrap">
				<StatusText tone={paused ? "red" : "green"}>
					{paused ? "Paused: sponsoring nothing" : "Accepting new sponsorships"}
				</StatusText>
				<ActionButton
					target={{ role: "PAUSER_ROLE" }}
					label={paused ? "Unpause" : "Pause"}
					icon={paused ? <LuPlay /> : <LuPause />}
					destructive={!paused}
					send={() => (paused ? client.unpause() : client.pause())}
					confirm={
						paused
							? undefined
							: {
									title: "Pause the paymaster",
									effect:
										"Every new sponsorship is refused until it is unpaused, for every tenant on this chain. Tenant withdrawals keep working.",
									confirmLabel: "Pause",
								}
					}
				/>
			</HStack>
		</Card>
	);
}

function SignersCard({
	client,
	signers,
}: {
	client: GianoPaymasterClient;
	signers: readonly Address[];
}) {
	const signer = useAddressInput();
	const address = signer.value;
	return (
		<Card
			title="Sponsorship signing keys"
			subtitle="Only these keys can authorise a sponsorship. Removing one takes effect immediately."
			needs="SIGNER_ADMIN_ROLE"
		>
			{signers.length === 0 ? (
				<Alert.Root status="error" size="sm">
					<Alert.Indicator />
					<Alert.Content>
						<Alert.Title>No signing keys</Alert.Title>
						<Alert.Description>
							Nothing can be sponsored until one is added.
						</Alert.Description>
					</Alert.Content>
				</Alert.Root>
			) : (
				<Stack gap="3">
					{signers.map((key) => (
						<HStack
							key={key}
							justify="space-between"
							align="flex-start"
							gap="3"
						>
							<AddressLabel address={key} label="Signing key" />
							<ActionButton
								target={{ role: "SIGNER_ADMIN_ROLE" }}
								label="Remove"
								icon={<LuTrash2 />}
								size="xs"
								destructive
								send={() => client.removeSigner(key)}
								confirm={{
									title: "Remove a signing key",
									effect: `Authorisations signed by ${key} stop validating at once, including any already handed to a client and not yet used.${signers.length === 1 ? " It is the only key: nothing can be sponsored until another is added." : ""}`,
									confirmLabel: "Remove key",
								}}
							/>
						</HStack>
					))}
				</Stack>
			)}
			<AddressInput input={signer} label="Add a signing key" />
			<ActionButton
				target={{ role: "SIGNER_ADMIN_ROLE" }}
				label="Add signing key"
				send={address ? () => client.addSigner(address) : undefined}
				onDone={signer.clear}
			/>
		</Card>
	);
}

function PricingCard({
	client,
	defaultFeeWei,
}: {
	client: GianoPaymasterClient;
	defaultFeeWei: bigint;
}) {
	// 0 is a fee: free sponsorship.
	const fee = useAmountInput(undefined, undefined, { allowZero: true });
	const feeWei = fee.value;
	return (
		<Card
			title="Pricing"
			subtitle="The platform fee charged per sponsored operation, unless a tenant has an override."
			needs="FEE_ADMIN_ROLE"
		>
			<Facts>
				<Fact label="Default fee">
					<Stack gap="1">
						<Amount wei={defaultFeeWei} decimals={6} />
						<QueuedMarker keys={queuedKeys.defaultFee} />
					</Stack>
				</Fact>
			</Facts>
			<AmountInput input={fee} label="New default fee" />
			<ActionButton
				target={{ operation: "setDefaultFee" }}
				label="Set default fee"
				send={
					feeWei !== undefined ? () => client.setDefaultFee(feeWei) : undefined
				}
				proposal={
					feeWei !== undefined ? { kind: "setDefaultFee", feeWei } : undefined
				}
				onDone={fee.clear}
			/>
		</Card>
	);
}

function ParametersCard({
	client,
	postOpGasAllowance,
	penaltyBps,
}: {
	client: GianoPaymasterClient;
	postOpGasAllowance: number;
	penaltyBps: number;
}) {
	const gas = useWholeNumberInput({ max: MAX_UINT32, unit: "gas" });
	const penalty = useInput(parsePenaltyBps);
	const gasValue = gas.value;
	const penaltyValue = penalty.value;
	return (
		<Card
			title="Operational parameters"
			subtitle="Bounds on the costs settlement cannot observe, charged as an upper bound on purpose."
			needs="PARAM_ADMIN_ROLE"
		>
			<Facts>
				<Fact label="Post-op gas allowance">
					{postOpGasAllowance.toLocaleString()} gas
				</Fact>
				<Fact label="Unused-gas penalty">
					{penaltyBps} bps ({(penaltyBps / 100).toFixed(2)}%)
				</Fact>
			</Facts>
			<WholeNumberInput
				input={gas}
				label="New post-op gas allowance"
				unit="gas"
				helper="Gas units charged for the settlement step's own gas."
			/>
			<ActionButton
				target={{ role: "PARAM_ADMIN_ROLE" }}
				label="Set post-op gas allowance"
				send={
					gasValue !== undefined
						? () => client.setPostOpGasAllowance(Number(gasValue))
						: undefined
				}
				onDone={gas.clear}
			/>
			<WholeNumberInput
				input={penalty}
				label="New unused-gas penalty"
				unit="bps"
				helper="Basis points of the execution gas limit, at most 5000 (50%)."
			/>
			<ActionButton
				target={{ role: "PARAM_ADMIN_ROLE" }}
				label="Set penalty"
				send={
					penaltyValue !== undefined
						? () => client.setPenaltyBps(Number(penaltyValue))
						: undefined
				}
				onDone={penalty.clear}
			/>
		</Card>
	);
}

function TreasuryCard({
	client,
	treasuryWei,
}: {
	client: GianoPaymasterClient;
	treasuryWei: bigint;
}) {
	const to = useAddressInput();
	const amount = useAmountInput(treasuryWei, "the treasury");
	const address = to.value;
	const wei = amount.value;
	const { deployment } = useConsole();
	return (
		<Card
			title="Treasury"
			subtitle="Platform fees accrued. Withdrawal is capped at what has accrued, which keeps tenant balances out of reach."
			needs="FEE_COLLECTOR_ROLE"
		>
			<Facts>
				<Fact label="Accrued">
					<Amount wei={treasuryWei} />
				</Fact>
			</Facts>
			<AddressInput input={to} label="Withdraw to" />
			<AmountInput input={amount} label="Amount" max={treasuryWei} />
			<ActionButton
				target={{ role: "FEE_COLLECTOR_ROLE" }}
				label="Withdraw fees"
				destructive
				send={
					address && wei ? () => client.withdrawFees(address, wei) : undefined
				}
				confirm={
					address && wei
						? {
								title: "Withdraw from the treasury",
								effect: `${amount.text} ${deployment.nativeCurrency.symbol} leaves the paymaster for ${address}. It cannot be pulled back.`,
								confirmLabel: "Withdraw",
							}
						: undefined
				}
				onDone={() => {
					to.clear();
					amount.clear();
				}}
			/>
		</Card>
	);
}

function StakeCard({
	client,
	stake,
}: {
	client: GianoPaymasterClient;
	stake: PaymasterOverview["stake"];
}) {
	const now = useChainNow(client);
	// With stake already locked, 0 is a value: the EntryPoint takes addStake with no value, which
	// locks an unlocking stake again or raises only the delay, without sending more funds.
	const amount = useAmountInput(undefined, undefined, {
		allowZero: stake.stakeWei > 0n,
	});
	const onChainDelay = stake.unstakeDelaySec
		? String(stake.unstakeDelaySec)
		: "86400";
	const delay = useWholeNumberInput(
		{ max: MAX_UINT32, unit: "seconds" },
		onChainDelay,
	);
	// The field shows the on-chain delay until the operator edits it, so another operator raising it
	// does not leave Add stake disabled as "too short" until the field is retyped.
	const shown = useRef(onChainDelay);
	const { text: delayText, setText: setDelayText } = delay;
	useEffect(() => {
		if (delayText === shown.current) setDelayText(onChainDelay);
		shown.current = onChainDelay;
	}, [onChainDelay, delayText, setDelayText]);
	const to = useAddressInput();
	const wei = amount.value;
	const delayValue = delay.value;
	const address = to.value;
	const unlocking = stake.withdrawTime > 0;
	const withdrawable = unlocking && now >= stake.withdrawTime;
	const delayZero = delayValue === 0n;
	const delayTooShort =
		delayValue !== undefined && delayValue < BigInt(stake.unstakeDelaySec);

	return (
		<Card
			title="Stake"
			subtitle="Bundlers reject an unstaked validating paymaster, which reaches a client as an unexplained failure."
			needs="STAKE_ADMIN_ROLE"
		>
			<Facts>
				<Fact label="Locked">
					{stake.staked || stake.stakeWei > 0n ? (
						<Amount wei={stake.stakeWei} />
					) : (
						"Not staked"
					)}
				</Fact>
				<Fact label="Unstake delay">
					{stake.unstakeDelaySec ? formatDuration(stake.unstakeDelaySec) : "—"}
				</Fact>
				<Fact label="State">
					{!unlocking ? (
						<StatusText tone={stake.staked ? "green" : "orange"}>
							{stake.staked ? "Staked and locked" : "Not staked"}
						</StatusText>
					) : withdrawable ? (
						<StatusText tone="orange">Unlocked: withdrawable now</StatusText>
					) : (
						<StatusText tone="orange">
							Unlocking: withdrawable from{" "}
							{new Date(stake.withdrawTime * 1000).toLocaleString()}
						</StatusText>
					)}
				</Fact>
			</Facts>

			<AmountInput
				input={amount}
				label="Add stake"
				helper={
					stake.stakeWei > 0n
						? "0 locks the stake again, or sets a longer delay, without adding funds."
						: undefined
				}
			/>
			<WholeNumberInput
				input={delay}
				label="Unstake delay"
				unit="seconds"
				helper={
					delayZero
						? "The EntryPoint requires an unstake delay above 0."
						: delayTooShort
							? `The EntryPoint refuses a shorter delay than the current ${formatDuration(stake.unstakeDelaySec)}.`
							: delayValue !== undefined
								? `${formatDuration(delayValue)}. Adding stake locks it again.`
								: undefined
				}
			/>
			<ActionButton
				target={{ role: "STAKE_ADMIN_ROLE" }}
				label="Add stake"
				send={
					wei !== undefined &&
					delayValue !== undefined &&
					!delayZero &&
					!delayTooShort
						? () => client.addStake(wei, Number(delayValue))
						: undefined
				}
				onDone={amount.clear}
			/>

			{stake.staked && !unlocking && (
				<ActionButton
					target={{ role: "STAKE_ADMIN_ROLE" }}
					label="Unlock stake"
					destructive
					send={() => client.unlockStake()}
					confirm={{
						title: "Unlock the stake",
						effect: `Bundlers stop accepting this paymaster as soon as it is unlocked, so sponsorship stops for every tenant. The stake can be withdrawn after ${formatDuration(stake.unstakeDelaySec)}; adding stake locks it again.`,
						confirmLabel: "Unlock",
					}}
				/>
			)}
			{unlocking && (
				<>
					<AddressInput input={to} label="Withdraw stake to" />
					<ActionButton
						target={{ role: "STAKE_ADMIN_ROLE" }}
						label="Withdraw stake"
						destructive
						disabled={!withdrawable}
						send={address ? () => client.withdrawStake(address) : undefined}
						confirm={
							address
								? {
										title: "Withdraw the stake",
										effect: `The whole stake goes to ${address}. The paymaster stays unstaked, and bundlers keep refusing it, until stake is added again.`,
										confirmLabel: "Withdraw stake",
									}
								: undefined
						}
						onDone={to.clear}
					/>
					{!withdrawable && (
						<Text fontSize="xs" color="fg.muted">
							Possible from{" "}
							{new Date(stake.withdrawTime * 1000).toLocaleString()}.
						</Text>
					)}
				</>
			)}
		</Card>
	);
}

/**
 * The chain's clock: the latest block's timestamp, read with every console refresh and carried
 * forward by the browser's clock between reads. The EntryPoint judges `withdrawTime` by
 * `block.timestamp`, and a devnet's chain time can be far from the browser's.
 */
function useChainNow(client: GianoPaymasterClient): number {
	const { block } = useConsole();
	const wall = useNow(15_000) / 1000;
	const [offset, setOffset] = useState(0);
	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: re-read with every console refresh
	useEffect(() => {
		let cancelled = false;
		client.publicClient.getBlock().then(
			(latest) => {
				if (!cancelled) setOffset(Number(latest.timestamp) - Date.now() / 1000);
			},
			() => undefined, // the browser's clock stands in until a read succeeds
		);
		return () => {
			cancelled = true;
		};
	}, [client, block]);
	return wall + offset;
}

/** Whether an address has code: an implementation without any would brick the proxy. */
function useHasCode(
	client: GianoPaymasterClient,
	address: Address | undefined,
): boolean | undefined {
	const [found, setFound] = useState<{ address: Address; code: boolean }>();
	useEffect(() => {
		if (!address) return;
		let cancelled = false;
		client.publicClient.getCode({ address }).then(
			(code) => {
				if (!cancelled) setFound({ address, code: !!code && code !== "0x" });
			},
			() => undefined,
		);
		return () => {
			cancelled = true;
		};
	}, [client, address]);
	return found && found.address === address ? found.code : undefined;
}

/** What an upgrade's call is, in a sentence: its size and selector, or nothing. */
function describeCall(calldata: `0x${string}`): string {
	if (calldata === "0x") return "";
	const bytes = (calldata.length - 2) / 2;
	return `, after running a call of ${bytes} byte${bytes === 1 ? "" : "s"}${bytes >= 4 ? ` (selector ${calldata.slice(0, 10)})` : ""}`;
}

function UpgradeCard({ client }: { client: GianoPaymasterClient }) {
	const { block } = useConsole();
	const [implementation, setImplementation] = useState<Address>();
	const [error, setError] = useState<string>();
	const next = useAddressInput();
	const data = useCalldataInput();
	const address = next.value;
	const calldata = data.value ?? "0x";
	const hasCode = useHasCode(client, address);
	const noCode = address !== undefined && hasCode === false;
	// Right after an upgrade an older read can land last: only the latest read's answer is kept.
	const generation = useRef(0);

	const read = useCallback(async () => {
		const current = ++generation.current;
		try {
			const found = await client.getImplementation();
			if (generation.current !== current) return;
			setImplementation(found);
			setError(undefined);
		} catch (cause) {
			if (generation.current === current) setError(describeError(cause));
		}
	}, [client]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: re-read with every console refresh
	useEffect(() => {
		void read();
	}, [read, block]);

	return (
		<Card
			title="Upgrade"
			subtitle="The paymaster is a UUPS proxy. An upgrade can do anything, including take tenant funds, so it waits out the timelock."
			needs="UPGRADER_ROLE"
		>
			{error && (
				<InlineError
					title="Could not read the implementation"
					error={error}
					retry={() => void read()}
					stale={implementation !== undefined}
				/>
			)}
			<Facts>
				<Fact label="Implementation">
					<Stack gap="1">
						{implementation ? (
							<AddressLabel address={implementation} label="Implementation" />
						) : (
							!error && <Text color="fg.muted">Reading…</Text>
						)}
						<QueuedMarker keys={queuedKeys.implementation} />
					</Stack>
				</Fact>
			</Facts>
			<AddressInput
				input={next}
				label="New implementation"
				helper={
					noCode
						? "No contract is deployed at this address on this chain."
						: undefined
				}
			/>
			<CalldataInput
				input={data}
				label="Call after upgrading (optional)"
				helper="Run on the new implementation in the same transaction, e.g. a reinitialiser."
			/>
			<ActionButton
				target={{ operation: "upgradeToAndCall" }}
				label="Upgrade"
				destructive
				// Checked for Propose too: a wrong address would otherwise surface only when the operation
				// executes, after the timelock's delay.
				disabled={data.error !== undefined || noCode || hasCode === undefined}
				send={
					address ? () => client.upgradeToAndCall(address, calldata) : undefined
				}
				proposal={
					address
						? {
								kind: "upgradeToAndCall",
								implementation: address,
								data: calldata,
							}
						: undefined
				}
				confirm={
					address
						? {
								title: "Upgrade the paymaster",
								effect: `The proxy delegates to ${address} from this transaction on${describeCall(calldata)}. Check it is the audited release.`,
								confirmLabel: "Upgrade",
							}
						: undefined
				}
				onDone={() => {
					next.clear();
					data.clear();
				}}
			/>
		</Card>
	);
}
