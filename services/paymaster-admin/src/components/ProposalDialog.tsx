import {
	formatDuration,
	type TenantView,
	TIMELOCKED_OPERATIONS,
	type TimelockProposalDraft,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Box,
	Button,
	Dialog,
	Field,
	HStack,
	Input,
	NativeSelect,
	Portal,
	Spinner,
	Stack,
	Text,
} from "@chakra-ui/react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { LuDownload, LuTrash2 } from "react-icons/lu";
import type { Hex } from "viem";
import { describeError } from "../lib/format";
import {
	buildProposal,
	downloadSafeBatch,
	type ProposalRequest,
	relativeTime,
	requestCalls,
	requestFunction,
} from "../lib/proposals";
import { useConsole } from "../shell/ConsoleContext";
import { ActionButton } from "./actions";
import { CallForm } from "./CallForm";
import { Copyable, notifyError, notifySuccess } from "./ui";

const SALT = /^0x[0-9a-fA-F]{64}$/;

function randomSalt(): Hex {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return `0x${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * A timelocked change, as a proposal (openspec N5, R5): one or more calls that execute together,
 * with the salt, delay and predecessor the operation will be scheduled with. It shows the operation
 * id, when it could execute, and the schedule, execute and cancel calldata; it saves the Safe
 * Transaction Builder batch for each step; and a wallet holding PROPOSER_ROLE can schedule it here.
 *
 * Every outcome is on screen and in the console log, not only in a toast: a proposal id an operator
 * missed is one they have to rebuild, and a rebuilt one has a different salt and a different id.
 */
export function ProposalDialog({
	request,
	tenants,
	onClose,
}: {
	request: ProposalRequest | undefined;
	tenants: readonly TenantView[];
	onClose: () => void;
}) {
	const { timelock, timelockAccess, timelockOperations, deployment } =
		useConsole();
	const [requests, setRequests] = useState<ProposalRequest[]>([]);
	const [salt, setSalt] = useState("");
	const [delay, setDelay] = useState("");
	const [predecessor, setPredecessor] = useState("");
	const [adding, setAdding] = useState(false);
	const [draft, setDraft] = useState<TimelockProposalDraft>();
	const [error, setError] = useState<string>();
	const [required, setRequired] = useState<bigint>();

	// Each open starts from the request it was opened with, under a fresh salt.
	useEffect(() => {
		setRequests(request ? [request] : []);
		setSalt(randomSalt());
		setDelay("");
		setPredecessor("");
		setDroppedPredecessor(undefined);
		setAdding(false);
		setRequired(undefined);
	}, [request]);

	// The proposal is rebuilt from the chain whenever its options change; while a salt or a delay is
	// being typed, only once the typing pauses rather than four reads a keystroke.
	const settledSalt = useDebounced(salt, 400);
	const settledDelay = useDebounced(delay, 400);
	// Until the typing settles, the draft is for the previous salt or delay: nothing may be scheduled
	// or saved from it while the fields show something else.
	const typing = salt !== settledSalt || delay !== settledDelay;
	const ready = typing ? undefined : draft;

	// A predecessor that is no longer pending (executed or cancelled) would leave the operation
	// unable to execute, found out only after the delay: it is cleared, and the field says why.
	const [droppedPredecessor, setDroppedPredecessor] = useState<string>();
	useEffect(() => {
		if (
			predecessor &&
			!timelockOperations.pending.some((pending) => pending.id === predecessor)
		) {
			setDroppedPredecessor(predecessor);
			setPredecessor("");
		}
	}, [predecessor, timelockOperations.pending]);

	const saltProblem =
		salt && !SALT.test(salt)
			? "A salt is 0x and 64 hex characters."
			: undefined;
	const delayProblem =
		delay.trim() && !/^\d+$/.test(delay.trim())
			? "A delay is a whole number of seconds."
			: undefined;

	useEffect(() => {
		setDraft(undefined);
		setError(undefined);
		if (
			!timelock ||
			requests.length === 0 ||
			saltProblem ||
			delayProblem ||
			!settledSalt ||
			!SALT.test(settledSalt) ||
			!/^\d*$/.test(settledDelay.trim())
		)
			return;
		let cancelled = false;
		buildProposal(timelock, requests, {
			salt: settledSalt as Hex,
			delay: settledDelay.trim() ? BigInt(settledDelay.trim()) : undefined,
			predecessor: predecessor ? (predecessor as Hex) : undefined,
		})
			.then((built) => {
				if (cancelled) return;
				// The schedule batch takes the RPC's chain id and the execute and cancel batches the
				// deployment's: a mismatch would make them disagree, so nothing is built from it.
				if (built.chainId !== deployment.chainId) {
					setError(
						`The RPC answers for chain ${built.chainId}, but this deployment is chain ${deployment.chainId}. Check the deployment's rpcUrl.`,
					);
					return;
				}
				setDraft(built);
				setRequired(built.requiredDelay);
				console.info(
					`[paymaster-admin] timelock proposal ${built.id}: ${built.summary} (delay ${formatDuration(built.delay)})`,
					built,
				);
			})
			.catch((cause: unknown) => {
				if (!cancelled) setError(describeError(cause));
			});
		return () => {
			cancelled = true;
		};
	}, [
		timelock,
		deployment.chainId,
		requests,
		settledSalt,
		settledDelay,
		predecessor,
		saltProblem,
		delayProblem,
	]);

	/**
	 * Each request's calls, decoded here rather than read off the draft: a proposal the timelock
	 * would refuse (a delay too short, an id already used) still says what it would have done.
	 */
	const summaries = useMemo(
		() =>
			timelock
				? requests.map((entry) =>
						requestCalls(timelock, entry).map(
							(call) =>
								timelock.decodeCall(call.target, call.data)?.summary ??
								"a call this console cannot decode",
						),
					)
				: [],
		[timelock, requests],
	);

	const save = (step: "schedule" | "execute" | "cancel") => {
		if (!ready || !timelock) return;
		try {
			const name = downloadSafeBatch(
				timelock.safeBatch(ready, step),
				step,
				ready.id,
			);
			notifySuccess(`Saved the Safe ${step} batch`, name);
		} catch (cause) {
			notifyError(`Could not save the Safe ${step} batch`, cause);
		}
	};

	const first = requests[0] && requestFunction(requests[0]);
	const operation = first ? TIMELOCKED_OPERATIONS[first] : undefined;
	const delayTooShort = error !== undefined && /shorter than/.test(error);

	return (
		<Dialog.Root
			open={request !== undefined}
			onOpenChange={(event) => !event.open && onClose()}
			size="lg"
			scrollBehavior="inside"
		>
			<Portal>
				<Dialog.Backdrop />
				<Dialog.Positioner>
					<Dialog.Content>
						<Dialog.Header>
							<Dialog.Title>Timelock proposal</Dialog.Title>
						</Dialog.Header>
						<Dialog.Body>
							<Stack gap="5">
								{!timelock && (
									<Alert.Root status="warning">
										<Alert.Indicator />
										<Alert.Description>
											This deployment has no timelock configured
											(timelockAddress in the console config).
										</Alert.Description>
									</Alert.Root>
								)}
								{operation ? (
									<Text fontSize="sm" color="fg.muted">
										{operation.functionName} is timelocked: it needs{" "}
										{operation.role}, which the timelock holds, because{" "}
										{operation.why}. A proposer schedules it, and it can execute
										once the delay has passed.
									</Text>
								) : (
									<Text fontSize="sm" color="fg.muted">
										The timelock administers itself: this change waits out its
										own delay like any other.
									</Text>
								)}

								<Section title="Calls, executed together">
									<Stack gap="2" data-testid="proposal-calls">
										{requests.map((entry, index) => (
											<HStack
												// biome-ignore lint/suspicious/noArrayIndexKey: a call's position is its identity in the batch
												key={index}
												justify="space-between"
												align="flex-start"
												borderWidth="1px"
												rounded="md"
												px="3"
												py="2"
											>
												<Stack gap="0">
													{(summaries[index] ?? [entry.kind]).map((line) => (
														<Text key={line} fontSize="sm">
															{line}
														</Text>
													))}
												</Stack>
												{requests.length > 1 && (
													<Button
														size="xs"
														variant="ghost"
														aria-label="Remove this call"
														onClick={() =>
															setRequests(
																requests.filter((_, at) => at !== index),
															)
														}
													>
														<LuTrash2 />
													</Button>
												)}
											</HStack>
										))}
									</Stack>
									{adding ? (
										<Box borderWidth="1px" rounded="md" p="3" mt="2">
											<CallForm
												tenants={tenants}
												actionLabel="Add to this operation"
												onAdd={(next) => {
													setRequests([...requests, next]);
													setAdding(false);
												}}
											/>
										</Box>
									) : (
										<Button
											size="xs"
											variant="ghost"
											mt="1"
											onClick={() => setAdding(true)}
										>
											Add a call
										</Button>
									)}
								</Section>

								<Section title="Options">
									<Stack gap="3">
										<Field.Root invalid={saltProblem !== undefined}>
											<Field.Label fontSize="sm">Salt</Field.Label>
											<Input
												size="sm"
												fontFamily="mono"
												value={salt}
												onChange={(event) => setSalt(event.target.value)}
											/>
											<Field.ErrorText>{saltProblem}</Field.ErrorText>
											<Field.HelperText>
												Random. The same calls under the same salt are the same
												operation.
											</Field.HelperText>
										</Field.Root>
										<Field.Root
											invalid={delayProblem !== undefined || delayTooShort}
										>
											<Field.Label fontSize="sm">Delay (seconds)</Field.Label>
											<Input
												size="sm"
												fontFamily="mono"
												inputMode="numeric"
												value={delay}
												placeholder={
													required !== undefined
														? String(required)
														: "the minimum"
												}
												onChange={(event) => setDelay(event.target.value)}
											/>
											<Field.ErrorText>
												{delayProblem ?? (delayTooShort ? error : undefined)}
											</Field.ErrorText>
											{!delayProblem && !delayTooShort && (
												<Field.HelperText>
													{required !== undefined
														? `At least ${formatDuration(required)}, the longest delay of these calls. Empty uses that.`
														: "Empty uses the timelock's minimum for these calls."}
												</Field.HelperText>
											)}
										</Field.Root>
										<Field.Root>
											<Field.Label fontSize="sm">Predecessor</Field.Label>
											<NativeSelect.Root size="sm">
												<NativeSelect.Field
													value={predecessor}
													onChange={(event) => {
														setPredecessor(event.currentTarget.value);
														setDroppedPredecessor(undefined);
													}}
													fontFamily="mono"
												>
													<option value="">None</option>
													{timelockOperations.pending.map((pending) => (
														<option key={pending.id} value={pending.id}>
															{pending.id}
														</option>
													))}
												</NativeSelect.Field>
												<NativeSelect.Indicator />
											</NativeSelect.Root>
											<Field.HelperText
												color={droppedPredecessor ? "orange.fg" : undefined}
											>
												{droppedPredecessor
													? `${droppedPredecessor.slice(0, 10)}… is no longer pending, so it was cleared: an operation waiting on it could never execute.`
													: "A pending operation that must execute first."}
											</Field.HelperText>
										</Field.Root>
									</Stack>
								</Section>

								{error && !delayTooShort && (
									<Alert.Root status="error">
										<Alert.Indicator />
										<Alert.Content>
											<Alert.Title>Could not build the proposal</Alert.Title>
											<Alert.Description>{error}</Alert.Description>
										</Alert.Content>
									</Alert.Root>
								)}
								{timelock && !ready && !error && requests.length > 0 && (
									<HStack gap="3">
										<Spinner size="sm" color="timelock.solid" />
										<Text fontSize="sm" color="fg.muted">
											Reading the delay from the timelock…
										</Text>
									</HStack>
								)}

								{ready && (
									<Section title="The operation">
										<Stack gap="2" data-testid="proposal-result">
											<Row label="Operation id">
												<Copyable value={ready.id} label="Operation id" />
											</Row>
											<Row label="Delay">
												<Text fontSize="sm">{formatDuration(ready.delay)}</Text>
											</Row>
											<Row label="Ready">
												<Text fontSize="sm">
													{new Date(
														ready.readyAtIfScheduledNow * 1000,
													).toLocaleString()}{" "}
													({relativeTime(ready.readyAtIfScheduledNow)}) if
													scheduled now
												</Text>
											</Row>
											<Row label="Schedule">
												<Calldata
													value={ready.schedule}
													label="Schedule calldata"
												/>
											</Row>
											<Row label="Execute">
												<Calldata
													value={ready.execute}
													label="Execute calldata"
												/>
											</Row>
											<Row label="Cancel">
												<Calldata
													value={ready.cancel}
													label="Cancel calldata"
												/>
											</Row>
										</Stack>
									</Section>
								)}
							</Stack>
						</Dialog.Body>
						<Dialog.Footer flexWrap="wrap" gap="2">
							<Button variant="ghost" onClick={onClose}>
								Close
							</Button>
							<Button
								variant="outline"
								size="sm"
								disabled={!ready}
								onClick={() => save("cancel")}
							>
								<LuDownload /> Safe batch (cancel)
							</Button>
							<Button
								variant="outline"
								size="sm"
								disabled={!ready}
								onClick={() => save("execute")}
							>
								<LuDownload /> Safe batch (execute)
							</Button>
							<Button
								colorPalette="timelock"
								size="sm"
								disabled={!ready}
								onClick={() => save("schedule")}
							>
								<LuDownload /> Safe batch (schedule)
							</Button>
							{timelock && (
								<ActionButton
									target={{
										gate: {
											allowed: timelockAccess.mayPropose,
											reason:
												"Needs the timelock's PROPOSER_ROLE: hand the schedule batch to the proposer.",
										},
									}}
									label="Schedule"
									send={ready ? () => timelock.schedule(ready) : undefined}
									onDone={onClose}
								/>
							)}
						</Dialog.Footer>
					</Dialog.Content>
				</Dialog.Positioner>
			</Portal>
		</Dialog.Root>
	);
}

/**
 * Calldata in full and copyable, as every on-chain value here is, but in a box a few lines high:
 * a batch's schedule calldata runs to kilobytes, and the dialog has more to say than that.
 */
function Calldata({ value, label }: { value: Hex; label: string }) {
	return (
		<Stack gap="1">
			<Box maxH="24" overflowY="auto" rounded="sm">
				<Copyable value={value} label={label} />
			</Box>
			<Text fontSize="xs" color="fg.muted">
				{(value.length - 2) / 2} bytes · click to copy
			</Text>
		</Stack>
	);
}

/** `value`, once it has stopped changing for `ms`. */
function useDebounced<T>(value: T, ms: number): T {
	const [settled, setSettled] = useState(value);
	useEffect(() => {
		const timer = setTimeout(() => setSettled(value), ms);
		return () => clearTimeout(timer);
	}, [value, ms]);
	return settled;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
	return (
		<Stack gap="2">
			<Text
				fontSize="xs"
				textTransform="uppercase"
				letterSpacing="wide"
				color="fg.muted"
			>
				{title}
			</Text>
			{children}
		</Stack>
	);
}

function Row({ label, children }: { label: string; children: ReactNode }) {
	return (
		<HStack gap="3" align="flex-start">
			<Text fontSize="xs" color="fg.muted" minW="24" textAlign="right" pt="0.5">
				{label}
			</Text>
			<Box minW="0">{children}</Box>
		</HStack>
	);
}
