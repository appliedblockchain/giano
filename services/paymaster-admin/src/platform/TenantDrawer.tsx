import {
	Alert,
	Badge,
	Box,
	Button,
	CloseButton,
	DataList,
	Drawer,
	HStack,
	Portal,
	Separator,
	Spinner,
	Stack,
	Table,
	Text,
	Wrap,
} from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";
import {
	LuKeyRound,
	LuPause,
	LuPencil,
	LuPlay,
	LuTrash2,
} from "react-icons/lu";
import { Copyable } from "../components/ui";
import { eth } from "../lib/format";
import type { HistoryEntry, TenantDetail } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { EditTenantDialog } from "./EditTenantDialog";
import {
	DeleteDialog,
	IssueKeyDialog,
	ResumeDialog,
	RevokeKeyDialog,
	SuspendDialog,
} from "./LifecycleDialogs";
import type { PlatformAreaProps } from "./PlatformArea";
import {
	actorLabel,
	LifecycleBadge,
	OnChainBadge,
	type OnChainState,
} from "./shared";

type Props = PlatformAreaProps & {
	slug: string;
	onClose: () => void;
	/** The registry list should re-read: something about this tenant changed. */
	onChanged: () => void;
	canAdminister: boolean;
	onChain: (tenantId: string) => OnChainState;
};

type Open =
	| "edit"
	| "suspend"
	| "resume"
	| "delete"
	| "issue-key"
	| { revoke: string; label: string }
	| undefined;

/**
 * One tenant in full (specs/PLATFORM-ADMIN-SPECS.md §11.2): fields, keys, usage, ledger and
 * history, and the actions its state allows — no more.
 */
export function TenantDrawer(props: Props) {
	const {
		slug,
		onClose,
		onChanged,
		canAdminister,
		onChain,
		client,
		refreshChain,
	} = props;
	const { run } = usePlatform();
	const [detail, setDetail] = useState<TenantDetail>();
	const [loadError, setLoadError] = useState<string>();
	const [history, setHistory] = useState<HistoryEntry[]>([]);
	const [next, setNext] = useState<string | null>(null);
	const [open, setOpen] = useState<Open>();

	const load = useCallback(async () => {
		const [read, page] = await Promise.all([
			run((api) => api.detail(slug)),
			run((api) => api.history(slug)),
		]);
		if (!read || !page) return;
		if (!read.ok) return setLoadError(read.error.message);
		setLoadError(undefined);
		setDetail(read.value);
		if (page.ok) {
			setHistory(page.value.entries);
			setNext(page.value.next);
		}
	}, [run, slug]);

	useEffect(() => {
		void load();
	}, [load]);

	const changed = () => {
		void load();
		onChanged();
	};

	const older = async () => {
		if (!next) return;
		const page = await run((api) => api.history(slug, next));
		if (page?.ok) {
			setHistory((entries) => [...entries, ...page.value.entries]);
			setNext(page.value.next);
		}
	};

	const tenant = detail?.tenant;
	const onChainState = tenant ? onChain(tenant.id) : "unknown";
	const chainProps = {
		client,
		canAdminister,
		onChain: onChainState,
		refreshChain,
	};

	return (
		<Drawer.Root
			open
			onOpenChange={(event) => !event.open && onClose()}
			size="lg"
		>
			<Portal>
				<Drawer.Backdrop />
				<Drawer.Positioner>
					<Drawer.Content>
						<Drawer.Header>
							<Drawer.Title>{slug}</Drawer.Title>
						</Drawer.Header>
						<Drawer.Body>
							{loadError && (
								<Alert.Root status="error" size="sm">
									<Alert.Indicator />
									<Alert.Content>
										<Alert.Description>{loadError}</Alert.Description>
									</Alert.Content>
								</Alert.Root>
							)}
							{!tenant && !loadError && <Spinner />}
							{tenant && detail && (
								<Stack gap="5">
									<Wrap gap="2">
										<LifecycleBadge status={tenant.status} />
										<OnChainBadge state={onChainState} />
										<Badge variant="outline">version {tenant.version}</Badge>
									</Wrap>

									<Wrap gap="2" data-testid="tenant-actions">
										{tenant.status === "active" && (
											<Button
												size="sm"
												variant="outline"
												onClick={() => setOpen("edit")}
											>
												<LuPencil /> Edit
											</Button>
										)}
										{tenant.status === "active" && (
											<Button
												size="sm"
												variant="outline"
												onClick={() => setOpen("issue-key")}
											>
												<LuKeyRound /> Issue key
											</Button>
										)}
										{tenant.status === "active" && (
											<Button
												size="sm"
												variant="outline"
												colorPalette="orange"
												onClick={() => setOpen("suspend")}
											>
												<LuPause /> Suspend
											</Button>
										)}
										{tenant.status === "suspended" && (
											<Button
												size="sm"
												variant="outline"
												onClick={() => setOpen("resume")}
											>
												<LuPlay /> Resume
											</Button>
										)}
										{tenant.status === "suspended" && (
											<Button
												size="sm"
												variant="outline"
												colorPalette="red"
												onClick={() => setOpen("delete")}
											>
												<LuTrash2 /> Delete
											</Button>
										)}
									</Wrap>

									<DataList.Root orientation="horizontal" size="sm">
										<Item label="Id">
											<Copyable value={tenant.id} label="Tenant id" />
										</Item>
										<Item label="Display name">{tenant.rpName}</Item>
										<Item label="Wallet origin">{tenant.walletOrigin}</Item>
										<Item label="RP ID">{tenant.rpId}</Item>
										<Item label="Expected origins">
											{list(tenant.expectedOrigins)}
										</Item>
										<Item label="dApp origins">
											{list(tenant.allowedDappOrigins)}
										</Item>
										<Item label="CORS origins">{list(tenant.corsOrigins)}</Item>
										<Item label="Registration">
											{tenant.openRegistration
												? "open"
												: "closed — needs an admin key"}
										</Item>
										<Item label="Policy">
											{Object.keys(tenant.policy).length ? (
												<Code value={tenant.policy} />
											) : (
												"deployment defaults"
											)}
										</Item>
										<Item label="Branding">
											{Object.keys(tenant.branding).length ? (
												<Code value={tenant.branding} />
											) : (
												"—"
											)}
											<Text fontSize="xs" color="fg.muted">
												stored, not yet read by any UI
											</Text>
										</Item>
										<Item label="Users">
											{detail.users} users · {detail.credentials} credentials
										</Item>
										<Item label="Last user operation">
											{detail.lastUseropAt
												? new Date(detail.lastUseropAt).toLocaleString()
												: "none"}
										</Item>
										{tenant.statusChangedAt && (
											<Item label="Status changed">
												{new Date(tenant.statusChangedAt).toLocaleString()}
											</Item>
										)}
									</DataList.Root>

									<Separator />
									<Box>
										<Text fontWeight="semibold" mb="2">
											Admin keys
										</Text>
										{detail.adminKeys.length === 0 ? (
											<Text fontSize="sm" color="fg.muted">
												None.
											</Text>
										) : (
											<Table.Root size="sm">
												<Table.Body>
													{detail.adminKeys.map((key) => (
														<Table.Row key={key.id}>
															<Table.Cell>{key.label ?? "—"}</Table.Cell>
															<Table.Cell fontFamily="mono" fontSize="xs">
																{key.hashPrefix}…
															</Table.Cell>
															<Table.Cell fontSize="xs" color="fg.muted">
																{actorLabel(key.createdBy)} ·{" "}
																{new Date(key.createdAt).toLocaleDateString()}
															</Table.Cell>
															<Table.Cell textAlign="end">
																{tenant.status !== "deleted" && (
																	<Button
																		size="xs"
																		variant="ghost"
																		colorPalette="red"
																		onClick={() =>
																			setOpen({
																				revoke: key.id,
																				label: key.label ?? key.hashPrefix,
																			})
																		}
																	>
																		Revoke
																	</Button>
																)}
															</Table.Cell>
														</Table.Row>
													))}
												</Table.Body>
											</Table.Root>
										)}
									</Box>

									<Box>
										<Text fontWeight="semibold" mb="2">
											Ledger
										</Text>
										{detail.ledger.length === 0 ? (
											<Text fontSize="sm" color="fg.muted">
												No balance on any paymaster.
											</Text>
										) : (
											detail.ledger.map((row) => (
												<Text key={row.chainId} fontFamily="mono" fontSize="xs">
													chain {row.chainId} · balance{" "}
													{eth(BigInt(row.balanceWei))} · deficit{" "}
													{eth(BigInt(row.deficitWei))} · at block{" "}
													{row.lastSyncedBlock ?? "—"}
												</Text>
											))
										)}
									</Box>

									<Separator />
									<Box>
										<Text fontWeight="semibold" mb="2">
											History
										</Text>
										<Stack gap="2" data-testid="tenant-history">
											{history.map((entry) => (
												<HStack key={entry.id} gap="3" align="flex-start">
													<Badge
														variant="subtle"
														minW="28"
														justifyContent="center"
													>
														{entry.action}
													</Badge>
													<Box>
														<Text fontSize="sm">{actorLabel(entry.actor)}</Text>
														<Text fontSize="xs" color="fg.muted">
															{new Date(entry.createdAt).toLocaleString()}
															{typeof entry.detail?.reason === "string" &&
																` · “${entry.detail.reason}”`}
														</Text>
													</Box>
												</HStack>
											))}
											{next && (
												<Box>
													<Button
														size="xs"
														variant="ghost"
														onClick={() => void older()}
													>
														Older entries
													</Button>
												</Box>
											)}
										</Stack>
									</Box>
								</Stack>
							)}
						</Drawer.Body>
						<Drawer.CloseTrigger asChild>
							<CloseButton size="sm" />
						</Drawer.CloseTrigger>
					</Drawer.Content>
				</Drawer.Positioner>
			</Portal>

			{tenant && (
				<>
					<EditTenantDialog
						open={open === "edit"}
						onClose={() => setOpen(undefined)}
						tenant={tenant}
						onSaved={changed}
						onConflict={() => void load()}
					/>
					<SuspendDialog
						open={open === "suspend"}
						onClose={() => setOpen(undefined)}
						onDone={changed}
						tenant={tenant}
						{...chainProps}
					/>
					<ResumeDialog
						open={open === "resume"}
						onClose={() => setOpen(undefined)}
						onDone={changed}
						tenant={tenant}
						{...chainProps}
					/>
					<DeleteDialog
						open={open === "delete"}
						onClose={() => setOpen(undefined)}
						onDone={changed}
						tenant={tenant}
					/>
					<IssueKeyDialog
						open={open === "issue-key"}
						onClose={() => setOpen(undefined)}
						onDone={changed}
						tenant={tenant}
					/>
					{typeof open === "object" && (
						<RevokeKeyDialog
							open
							onClose={() => setOpen(undefined)}
							onDone={changed}
							tenant={tenant}
							keyId={open.revoke}
							keyLabel={open.label}
						/>
					)}
				</>
			)}
		</Drawer.Root>
	);
}

function Item({
	label,
	children,
}: {
	label: string;
	children: React.ReactNode;
}) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="36">{label}</DataList.ItemLabel>
			<DataList.ItemValue>
				<Box>{children}</Box>
			</DataList.ItemValue>
		</DataList.Item>
	);
}

const list = (values: string[]) =>
	values.length === 0 ? (
		"—"
	) : (
		<Stack gap="0">
			{values.map((value) => (
				<Text key={value} fontFamily="mono" fontSize="xs">
					{value}
				</Text>
			))}
		</Stack>
	);

function Code({ value }: { value: unknown }) {
	return (
		<Text as="pre" fontFamily="mono" fontSize="xs" whiteSpace="pre-wrap">
			{JSON.stringify(value, null, 2)}
		</Text>
	);
}
