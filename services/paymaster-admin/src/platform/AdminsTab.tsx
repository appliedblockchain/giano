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
import { LuPlus, LuRefreshCw, LuTrash2 } from "react-icons/lu";
import { Copyable, SectionCard } from "../components/ui";
import type {
	PlatformAdminHistoryEntry,
	PlatformAdminRow,
} from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { ActionDialog, usePlatformAction } from "./LifecycleDialogs";
import { actorLabel, issuesByField } from "./shared";

const ID_PATTERN = /^[a-z0-9-]{1,64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

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

	const load = useCallback(async () => {
		setLoading(true);
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

	return (
		<Stack gap="4">
			<SectionCard
				title={`Admins${admins ? ` (${admins.length})` : ""}`}
				subtitle="The wallets that may sign in to this Platform area. Changes take effect on the next request."
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
								<Alert.Description>{loadError}</Alert.Description>
							</Alert.Content>
						</Alert.Root>
					)}
					<Table.ScrollArea borderWidth="1px" rounded="md">
						<Table.Root size="sm">
							<Table.Header>
								<Table.Row>
									<Table.ColumnHeader>PlatformAdmin</Table.ColumnHeader>
									<Table.ColumnHeader>Address</Table.ColumnHeader>
									<Table.ColumnHeader>Added by</Table.ColumnHeader>
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
											<Table.Cell textAlign="end">
												{/* the API refuses removing yourself or the last platform admin; so does the UI */}
												{!isMe && admins!.length > 1 && (
													<Button
														size="xs"
														variant="ghost"
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
								<Box>
									<Text fontSize="sm">
										{entry.adminId}{" "}
										<Text
											as="span"
											fontFamily="mono"
											fontSize="xs"
											color="fg.muted"
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

function AddAdminDialog({
	onClose,
	onDone,
}: {
	onClose: () => void;
	onDone: () => void;
}) {
	const { act, busy, error } = usePlatformAction();
	const [id, setId] = useState("");
	const [address, setAddress] = useState("");
	const issues = issuesByField(error);
	const valid = ID_PATTERN.test(id) && ADDRESS_PATTERN.test(address.trim());

	const confirm = async () => {
		const result = await act((api) => api.addAdmin(id, address.trim()));
		if (result?.ok) {
			console.log("[admins] added", result.value);
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
			error={error}
			disabled={!valid}
			onConfirm={() => void confirm()}
		>
			<Stack gap="3">
				<Text fontSize="sm">
					The new platform admin can sign in with this wallet straight away,
					manage tenants, and add and remove platform admins too.
				</Text>
				<Field.Root
					invalid={Boolean(issues.id) || (id !== "" && !ID_PATTERN.test(id))}
				>
					<Field.Label>Id</Field.Label>
					<Input
						value={id}
						onChange={(event) => setId(event.target.value)}
						placeholder="admin-oncall"
						autoComplete="off"
					/>
					<Field.HelperText>
						Lowercase letters, digits and dashes. Shown in logs and history.
					</Field.HelperText>
				</Field.Root>
				<Field.Root
					invalid={
						Boolean(issues.address) ||
						(address !== "" && !ADDRESS_PATTERN.test(address.trim()))
					}
				>
					<Field.Label>Wallet address</Field.Label>
					<Input
						value={address}
						onChange={(event) => setAddress(event.target.value)}
						placeholder="0x…"
						fontFamily="mono"
						autoComplete="off"
					/>
				</Field.Root>
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
			console.log("[admins] removed", admin.id);
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
				<b>{admin.id}</b> ({admin.address}) can no longer sign in, and any
				session they have open ends on its next request.
			</Text>
		</ActionDialog>
	);
}
