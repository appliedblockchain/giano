import {
	formatDuration,
	type GianoTimelockClient,
	TIMELOCKED_OPERATIONS,
	type TimelockProposalDraft,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	Alert,
	Button,
	Dialog,
	HStack,
	Portal,
	Spinner,
	Stack,
	Text,
} from "@chakra-ui/react";
import { type ReactNode, useEffect, useState } from "react";
import { LuDownload } from "react-icons/lu";
import { describeError } from "../lib/format";
import {
	buildProposal,
	downloadSafeBatch,
	type ProposalRequest,
	relativeTime,
	requestFunction,
} from "../lib/proposals";
import { Copyable, notifyError, notifySuccess } from "./ui";

/**
 * A timelocked change, as a proposal rather than a transaction (G9, R5).
 *
 * Built the moment it opens, with the delay read from the timelock, and never sent: the console
 * shows what will happen, its operation id and when it could execute, the calldata for each step,
 * and the Safe Transaction Builder file that schedules it. The proposer is a Safe (R3), so the
 * last mile is the Safe's — this dialog's job is that nobody hand-encodes anything on the way.
 *
 * Every outcome is on screen and in the console log, not only in a toast: a proposal id an operator
 * missed is one they have to rebuild, and a rebuilt one has a different salt and a different id.
 */
export function ProposalDialog({
	timelock,
	request,
	onClose,
}: {
	timelock: GianoTimelockClient | undefined;
	request: ProposalRequest | undefined;
	onClose: () => void;
}) {
	const [draft, setDraft] = useState<TimelockProposalDraft>();
	const [error, setError] = useState<string>();
	const [saved, setSaved] = useState<string[]>([]);

	useEffect(() => {
		setDraft(undefined);
		setError(undefined);
		setSaved([]);
		if (!request || !timelock) return;

		let cancelled = false;
		buildProposal(timelock, request)
			.then((built) => {
				if (cancelled) return;
				setDraft(built);
				console.info(
					`[paymaster-admin] timelock proposal ${built.id}: ${built.summary} (delay ${formatDuration(built.delay)})`,
					built,
				);
			})
			.catch((cause: unknown) => {
				if (cancelled) return;
				setError(describeError(cause));
				notifyError("Could not build the timelock proposal", cause);
			});
		return () => {
			cancelled = true;
		};
	}, [request, timelock]);

	const save = (step: "schedule" | "execute") => {
		if (!draft || !timelock) return;
		try {
			const name = downloadSafeBatch(
				timelock.safeBatch(draft, step),
				step,
				draft.id,
			);
			setSaved((previous) => [...previous, name]);
			notifySuccess(`Saved the Safe ${step} batch`, name);
		} catch (cause) {
			notifyError(`Could not save the Safe ${step} batch`, cause);
		}
	};

	const operation = request
		? TIMELOCKED_OPERATIONS[requestFunction(request)]
		: undefined;

	return (
		<Dialog.Root
			open={request !== undefined}
			onOpenChange={(event) => !event.open && onClose()}
			size="lg"
		>
			<Portal>
				<Dialog.Backdrop />
				<Dialog.Positioner>
					<Dialog.Content>
						<Dialog.Header>
							<Dialog.Title>Timelock proposal</Dialog.Title>
						</Dialog.Header>
						<Dialog.Body>
							<Stack gap="4">
								{operation && (
									<Text fontSize="sm" color="fg.muted">
										{operation.functionName} is timelocked: it needs{" "}
										{operation.role}, which the timelock holds, because{" "}
										{operation.why}. Nothing is sent from this console — a
										proposer (the Safe) schedules it, and it can execute once
										the delay has passed.
									</Text>
								)}

								{!timelock && (
									<Alert.Root status="warning">
										<Alert.Indicator />
										<Alert.Description>
											This deployment has no timelock configured
											(timelockAddress in the console config).
										</Alert.Description>
									</Alert.Root>
								)}

								{error && (
									<Alert.Root status="error">
										<Alert.Indicator />
										<Alert.Content>
											<Alert.Title>Could not build the proposal</Alert.Title>
											<Alert.Description>{error}</Alert.Description>
										</Alert.Content>
									</Alert.Root>
								)}

								{timelock && !draft && !error && (
									<HStack gap="3">
										<Spinner size="sm" color="brand.solid" />
										<Text fontSize="sm" color="fg.muted">
											Reading the delay from the timelock…
										</Text>
									</HStack>
								)}

								{draft && (
									<>
										<Stack gap="2">
											<Row label="What">
												<Text fontSize="sm" fontWeight="medium">
													{draft.summary}
												</Text>
											</Row>
											<Row label="Operation id">
												<Copyable value={draft.id} label="Operation id" />
											</Row>
											<Row label="Timelock">
												<Copyable value={draft.timelock} label="Timelock" />
											</Row>
											<Row label="Delay">
												<Text fontSize="sm">{formatDuration(draft.delay)}</Text>
											</Row>
											<Row label="Ready">
												<Text fontSize="sm">
													{new Date(
														draft.readyAtIfScheduledNow * 1000,
													).toLocaleString()}{" "}
													({relativeTime(draft.readyAtIfScheduledNow)}) if
													scheduled now
												</Text>
											</Row>
											<Row label="Salt">
												<Copyable value={draft.salt} label="Salt" />
											</Row>
										</Stack>

										<Stack gap="2">
											<Text fontSize="sm" fontWeight="medium">
												1. A proposer sends to the timelock (schedule)
											</Text>
											<Copyable
												value={draft.schedule}
												label="Schedule calldata"
											/>
											<Text fontSize="sm" fontWeight="medium">
												2. Once ready, an executor sends (execute)
											</Text>
											<Copyable
												value={draft.execute}
												label="Execute calldata"
											/>
											<Text fontSize="sm" fontWeight="medium">
												To cancel while it is pending, a canceller sends
											</Text>
											<Copyable value={draft.cancel} label="Cancel calldata" />
										</Stack>

										{saved.length > 0 && (
											<Text fontSize="sm" color="accent.fg">
												Saved {saved.join(", ")} — upload it in the Safe's
												Transaction Builder.
											</Text>
										)}
									</>
								)}
							</Stack>
						</Dialog.Body>
						<Dialog.Footer>
							<Button variant="ghost" onClick={onClose}>
								Close
							</Button>
							<Button
								variant="outline"
								disabled={!draft}
								onClick={() => save("execute")}
							>
								<LuDownload /> Safe batch (execute)
							</Button>
							<Button
								colorPalette="brand"
								disabled={!draft}
								onClick={() => save("schedule")}
							>
								<LuDownload /> Safe batch (schedule)
							</Button>
						</Dialog.Footer>
					</Dialog.Content>
				</Dialog.Positioner>
			</Portal>
		</Dialog.Root>
	);
}

function Row({ label, children }: { label: string; children: ReactNode }) {
	return (
		<HStack gap="3" align="flex-start">
			<Text fontSize="xs" color="fg.muted" minW="24" textAlign="right" pt="0.5">
				{label}
			</Text>
			{children}
		</HStack>
	);
}
