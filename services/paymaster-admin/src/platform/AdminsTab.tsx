import {
	Alert,
	Badge,
	Box,
	Button,
	Field,
	HStack,
	Input,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";
import { LuLogOut, LuPlus, LuRefreshCw, LuTrash2 } from "react-icons/lu";
import { AddressInput, useAddressInput } from "../components/inputs";
import { InlineError, StatusText } from "../components/status";
import {
	Copyable,
	notifyError,
	notifySuccess,
	SectionCard,
} from "../components/ui";
import { describeError } from "../lib/format";
import type {
	PlatformAdminHistoryEntry,
	PlatformAdminRow,
	PlatformAdminSession,
} from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { ActionDialog, usePlatformAction } from "./LifecycleDialogs";
import { actorLabel, issuesByField } from "./shared";

const ID_PATTERN = /^[a-z0-9-]{1,64}$/;

/**
 * Who may sign in here (specs/PLATFORM-ADMIN-SPECS.md §4.1). The list lives in wallet-api's
 * database: seeded once per environment, then managed from this tab. An added platform admin can sign in
 * at once; a removed one is signed out on their next request. Nobody can remove themselves or the
 * last platform admin, so the deployment always has someone who can administer it.
 */
export function AdminsTab() {
	const { run, session } = usePlatform();
	const [admins, setAdmins] = useState<PlatformAdminRow[]>();
	const [history, setHistory] = useState<PlatformAdminHistoryEntry[]>([]);
	const [loading, setLoading] = useState(false);
	const [loadError, setLoadError] = useState<string>();
	const [adding, setAdding] = useState(false);
	const [removing, setRemoving] = useState<PlatformAdminRow>();
	// Bumped by every load: Your sessions reloads with the admins, so one refresh updates both.
	const [revision, setRevision] = useState(0);

	const load = useCallback(async () => {
		setLoading(true);
		setRevision((current) => current + 1);
		try {
			const [list, changes] = await Promise.all([
				run((api) => api.admins()),
				run((api) => api.platformAdminHistory()),
			]);
			if (!list || !changes) return; // the session ended; the area is back on sign-in
			if (!list.ok) return setLoadError(list.error.message);
			setLoadError(undefined);
			setAdmins(list.value.admins);
			if (changes.ok) setHistory(changes.value.entries);
		} catch (cause) {
			setLoadError(cause instanceof Error ? cause.message : String(cause));
		} finally {
			setLoading(false);
		}
	}, [run]);

	useEffect(() => {
		void load();
	}, [load]);

	const me = session?.admin.address.toLowerCase();
	// B6, read where wallet-api reports it: an older one lists admins without these fields (D11).
	const signIns = admins?.some((admin) => admin.activeSessions !== undefined);

	return (
		<Stack gap="4">
			<SectionCard
				title={`Admins${admins ? ` (${admins.length})` : ""}`}
				subtitle="The wallets that may sign in to this console. An added admin can sign in at once; removing one ends their sessions at once, on their next request."
				action={
					<HStack>
						<Button
							size="sm"
							variant="ghost"
							onClick={() => void load()}
							loading={loading}
							aria-label="Refresh admins"
						>
							<LuRefreshCw />
						</Button>
						<Button
							size="sm"
							colorPalette="brand"
							onClick={() => setAdding(true)}
						>
							<LuPlus /> Add admin
						</Button>
					</HStack>
				}
			>
				<Stack gap="3">
					{loadError && (
						<Alert.Root status="error" size="sm">
							<Alert.Indicator />
							<Alert.Content>
								<Alert.Title>Could not read the admins</Alert.Title>
								<Alert.Description overflowWrap="anywhere">
									{loadError}
								</Alert.Description>
							</Alert.Content>
						</Alert.Root>
					)}
					<Table.ScrollArea borderWidth="1px" rounded="md">
						<Table.Root size="sm">
							<Table.Header>
								<Table.Row>
									<Table.ColumnHeader>Admin</Table.ColumnHeader>
									<Table.ColumnHeader>Address</Table.ColumnHeader>
									<Table.ColumnHeader>Added by</Table.ColumnHeader>
									{signIns && (
										<Table.ColumnHeader>Last sign-in</Table.ColumnHeader>
									)}
									<Table.ColumnHeader />
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{(admins ?? []).map((admin) => {
									const isMe = admin.address === me;
									return (
										<Table.Row
											key={admin.id}
											data-testid={`admin-row-${admin.id}`}
										>
											<Table.Cell>
												<HStack gap="2">
													<Text fontWeight="medium">{admin.id}</Text>
													{isMe && (
														<Badge
															size="sm"
															variant="subtle"
															colorPalette="brand"
														>
															you
														</Badge>
													)}
												</HStack>
											</Table.Cell>
											<Table.Cell>
												<Copyable
													value={admin.address}
													label="Platform admin address"
												/>
											</Table.Cell>
											<Table.Cell fontSize="xs" color="fg.muted">
												{actorLabel(admin.addedBy)} ·{" "}
												{new Date(admin.createdAt).toLocaleDateString()}
											</Table.Cell>
											{signIns && (
												<Table.Cell fontSize="xs" data-testid="admin-sign-in">
													<Text>
														{admin.lastSignInAt
															? new Date(admin.lastSignInAt).toLocaleString()
															: "never"}
													</Text>
													<Text color="fg.muted">
														{admin.activeSessions ?? 0} open session
														{admin.activeSessions === 1 ? "" : "s"}
													</Text>
												</Table.Cell>
											)}
											<Table.Cell textAlign="end">
												{/* the API refuses removing yourself or the last platform admin; so does the UI, and says why */}
												{isMe ? (
													<Text fontSize="xs" color="fg.muted">
														You cannot remove yourself: ask another admin.
													</Text>
												) : (admins?.length ?? 0) <= 1 ? (
													<Text fontSize="xs" color="fg.muted">
														The last admin cannot be removed.
													</Text>
												) : (
													<Button
														size="xs"
														variant="outline"
														colorPalette="red"
														onClick={() => setRemoving(admin)}
													>
														<LuTrash2 /> Remove
													</Button>
												)}
											</Table.Cell>
										</Table.Row>
									);
								})}
							</Table.Body>
						</Table.Root>
					</Table.ScrollArea>
				</Stack>
			</SectionCard>

			{session && (
				<YourSessions
					adminId={session.admin.id}
					revision={revision}
					onChanged={() => void load()}
				/>
			)}

			<SectionCard
				title="Changes"
				subtitle="Every platform admin added or removed, newest first."
			>
				{history.length === 0 ? (
					<Text fontSize="sm" color="fg.muted">
						Nothing recorded yet.
					</Text>
				) : (
					<Stack gap="2" data-testid="admin-history">
						{history.map((entry) => (
							<HStack key={entry.id} gap="3" align="flex-start">
								<Badge variant="subtle" minW="20" justifyContent="center">
									{entry.action}
								</Badge>
								<Box minW="0">
									<Text fontSize="sm">
										{entry.adminId}{" "}
										<Text
											as="span"
											fontFamily="mono"
											fontSize="xs"
											color="fg.muted"
											wordBreak="break-all"
										>
											{entry.address}
										</Text>
									</Text>
									<Text fontSize="xs" color="fg.muted">
										by {actorLabel(entry.actor)} ·{" "}
										{new Date(entry.createdAt).toLocaleString()}
									</Text>
								</Box>
							</HStack>
						))}
					</Stack>
				)}
			</SectionCard>

			{adding && (
				<AddAdminDialog
					onClose={() => setAdding(false)}
					onDone={() => void load()}
				/>
			)}
			{removing && (
				<RemoveAdminDialog
					admin={removing}
					onClose={() => setRemoving(undefined)}
					onDone={() => void load()}
				/>
			)}
		</Stack>
	);
}

/**
 * Your own sessions from the last 30 days (B6, D15), with *End* on each open one but this. Absent
 * where wallet-api does not serve them (D11). Another admin's sessions end when they are removed.
 * Reloads with the admins (`revision`), and ending one reloads both, so your open count follows.
 */
function YourSessions({
	adminId,
	revision,
	onChanged,
}: {
	adminId: string;
	revision: number;
	onChanged: () => void;
}) {
	const { run } = usePlatform();
	const [sessions, setSessions] = useState<PlatformAdminSession[]>();
	const [served, setServed] = useState(true);
	const [error, setError] = useState<string>();
	const [ending, setEnding] = useState<string>();

	const load = useCallback(async () => {
		try {
			const result = await run((api) => api.adminSessions(adminId));
			if (!result) return;
			if (result.ok) {
				setSessions(result.value.sessions);
				setError(undefined);
			} else if (result.error.status === 404) setServed(false);
			else setError(result.error.message);
		} catch (cause) {
			// A network failure, or a proxy's non-JSON 5xx: run rethrows all but a lost session.
			setError(describeError(cause));
		}
	}, [run, adminId]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `revision` is a trigger: reload with the admins
	useEffect(() => {
		void load();
	}, [load, revision]);

	const end = async (session: PlatformAdminSession) => {
		setEnding(session.id);
		try {
			const result = await run((api) => api.endSession(adminId, session.id));
			if (!result) return;
			if (result.ok) {
				notifySuccess("Session ended", "It is refused from its next request.");
				onChanged();
			} else notifyError("Could not end the session", result.error.message);
		} catch (cause) {
			notifyError("Could not end the session", describeError(cause));
		} finally {
			setEnding(undefined);
		}
	};

	if (!served) return null;
	const now = Date.now();
	return (
		<SectionCard
			title="Your sessions"
			subtitle="Where you have signed in during the last 30 days, newest first. End any you do not recognise, or no longer use."
		>
			<Stack gap="0" data-testid="your-sessions">
				{error && (
					<InlineError
						title="Could not read your sessions"
						error={error}
						retry={() => void load()}
					/>
				)}
				{sessions?.map((session, index) => {
					const open =
						!session.revokedAt && Date.parse(session.expiresAt) > now;
					return (
						<HStack
							key={session.id}
							justify="space-between"
							align="flex-start"
							gap="4"
							py="3"
							flexWrap="wrap"
							borderTopWidth={index === 0 ? "0" : "1px"}
							data-testid={`session-${session.id}`}
						>
							<Stack gap="1" minW="0" flex="1">
								<HStack gap="2" flexWrap="wrap">
									<StatusText tone={open ? "green" : "gray"}>
										{open ? "open" : session.revokedAt ? "ended" : "expired"}
									</StatusText>
									{session.current && (
										<Badge size="sm" variant="subtle" colorPalette="brand">
											this session
										</Badge>
									)}
									<Text fontSize="sm">
										signed in {new Date(session.createdAt).toLocaleString()}
									</Text>
								</HStack>
								<Text fontSize="xs" color="fg.muted" wordBreak="break-word">
									{session.revokedAt
										? `ended ${new Date(session.revokedAt).toLocaleString()}`
										: `${open ? "ends" : "ended"} ${new Date(session.expiresAt).toLocaleString()}`}{" "}
									· chain {session.chainId} ·{" "}
									{session.userAgent ?? "no browser recorded"}
								</Text>
							</Stack>
							{open && !session.current && (
								<Button
									size="xs"
									variant="outline"
									loading={ending === session.id}
									onClick={() => void end(session)}
								>
									<LuLogOut /> End
								</Button>
							)}
						</HStack>
					);
				})}
			</Stack>
		</SectionCard>
	);
}

function AddAdminDialog({
	onClose,
	onDone,
}: {
	onClose: () => void;
	onDone: () => void;
}) {
	const { act, busy, error } = usePlatformAction();
	const [id, setId] = useState("");
	const wallet = useAddressInput();
	const issues = issuesByField(error);
	const address = wallet.value;
	const idProblem =
		id !== "" && !ID_PATTERN.test(id)
			? "Lowercase letters, digits and dashes only, at most 64."
			: issues.id?.join(" · ");

	const confirm = async () => {
		if (!address) return;
		const result = await act((api) => api.addAdmin(id, address));
		if (result?.ok) {
			onDone();
			onClose();
		} else if (result) {
			console.error("[admins] add refused", result.error);
		}
	};

	return (
		<ActionDialog
			open
			onClose={onClose}
			title="Add platform admin"
			confirmLabel="Add admin"
			busy={busy}
			error={error && !error.issues ? error : undefined}
			disabled={!ID_PATTERN.test(id) || !address}
			onConfirm={() => void confirm()}
		>
			<Stack gap="3">
				<Text fontSize="sm">
					The new platform admin can sign in with this wallet straight away,
					manage tenants, and add and remove platform admins too.
				</Text>
				<Field.Root invalid={idProblem !== undefined}>
					<Field.Label>Id</Field.Label>
					<Input
						value={id}
						onChange={(event) => setId(event.target.value)}
						placeholder="admin-oncall"
						autoComplete="off"
					/>
					{idProblem ? (
						<Field.ErrorText>{idProblem}</Field.ErrorText>
					) : (
						<Field.HelperText>
							Lowercase letters, digits and dashes. Shown in logs and history.
						</Field.HelperText>
					)}
				</Field.Root>
				<AddressInput
					input={wallet}
					label="Wallet address"
					helper={issues.address?.join(" · ")}
				/>
			</Stack>
		</ActionDialog>
	);
}

function RemoveAdminDialog({
	admin,
	onClose,
	onDone,
}: {
	admin: PlatformAdminRow;
	onClose: () => void;
	onDone: () => void;
}) {
	const { act, busy, error } = usePlatformAction();
	const confirm = async () => {
		const result = await act((api) => api.removeAdmin(admin.id));
		if (result?.ok) {
			onDone();
			onClose();
		} else if (result) {
			console.error("[admins] remove refused", result.error);
		}
	};
	return (
		<ActionDialog
			open
			onClose={onClose}
			title={`Remove ${admin.id}`}
			confirmLabel="Remove admin"
			confirmPalette="red"
			busy={busy}
			error={error}
			onConfirm={() => void confirm()}
		>
			<Text fontSize="sm">
				<b>{admin.id}</b> ({admin.address}) can no longer sign in, and every
				session they have open ends at once, on its next request.
			</Text>
		</ActionDialog>
	);
}
