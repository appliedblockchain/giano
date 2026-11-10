import type { GianoPaymasterClient } from "@appliedblockchain/giano-paymaster-sdk";
import {
	Badge,
	Box,
	Button,
	DataList,
	Heading,
	HStack,
	SimpleGrid,
	Spinner,
	Stack,
	Table,
	Text,
	Wrap,
} from "@chakra-ui/react";
import {
	type ReactNode,
	useCallback,
	useEffect,
	useRef,
	useState,
} from "react";
import {
	LuArrowLeft,
	LuKeyRound,
	LuPause,
	LuPencil,
	LuPlay,
	LuTrash2,
} from "react-icons/lu";
import { InlineError } from "../components/status";
import { Copyable, SectionCard } from "../components/ui";
import { UsageCard, useUsage } from "../components/usage";
import { getAdminConfig } from "../config";
import { describeError } from "../lib/format";
import type { HistoryEntry, TenantDetail } from "../lib/platform-api";
import { usePlatform } from "../lib/platform-session";
import { Link, TAB_PATHS } from "../lib/router";
import { mergeFirstPage, type TenantRow } from "../lib/tenants";
import { EditTenantDialog } from "../platform/EditTenantDialog";
import {
	DeleteDialog,
	IssueKeyDialog,
	ResumeDialog,
	RevokeKeyDialog,
	SuspendDialog,
} from "../platform/LifecycleDialogs";
import {
	actorLabel,
	LifecycleBadge,
	OnChainBadge,
	type PlatformAreaProps,
} from "../platform/shared";
import { useConsole } from "../shell/ConsoleContext";
import { OnChainCard } from "./OnChainCard";
import { OtherDeployments, useOtherDeployments } from "./OtherDeployments";
import { PolicyView } from "./PolicyFields";
import { TenantActivity } from "./TenantActivity";
import { TenantHistory } from "./TenantHistory";

type Open =
	| "edit"
	| "suspend"
	| "resume"
	| "delete"
	| "issue-key"
	| { revoke: string; label: string }
	| undefined;

/**
 * One tenant in full, at `/tenants/<slug>` (openspec D3, platform-console-tenants): the registry
 * record and its keys, the tenant on the selected chain and on every other one, its recent
 * sponsorships, and its history — with the actions its state allows and no more.
 *
 * A tenant with no registry row, or any tenant on a console without the platform API, has only the
 * on-chain half.
 */
export function TenantPage({
	row,
	registryComplete,
	client,
	platformProps,
	lastUpdated,
	onRegistryChanged,
}: {
	row: TenantRow;
	/** Whether a tenant missing from the registry is known not to be in it (deleted ones included). */
	registryComplete: boolean;
	/** Undefined while the paymaster has not been read; the registry half still shows. */
	client: GianoPaymasterClient | undefined;
	platformProps: PlatformAreaProps;
	lastUpdated: Date | undefined;
	/** Something about the tenant changed in the registry: the list should re-read. */
	onRegistryChanged: () => void;
}) {
	const { myRoles } = useConsole();
	const slug = row.registry?.slug;
	const record = useTenantRecord(slug, lastUpdated);
	const others = useOtherDeployments(row.id, lastUpdated);
	const [open, setOpen] = useState<Open>();
	const tenant = record.detail?.tenant;

	const changed = () => {
		void record.reload();
		onRegistryChanged();
	};
	const chainProps = {
		client,
		canAdminister: myRoles.includes("TENANT_ADMIN_ROLE"),
		onChain: row.state,
		refreshChain: platformProps.refreshChain,
		others,
	};

	return (
		<Stack gap="4">
			<Link
				to={TAB_PATHS.tenants}
				fontSize="sm"
				color="fg.muted"
				display="inline-flex"
				alignItems="center"
				gap="1"
			>
				<LuArrowLeft aria-hidden="true" /> Tenants
			</Link>
			<HStack
				justify="space-between"
				align="flex-start"
				flexWrap="wrap"
				gap="3"
				data-testid="tenant-header"
			>
				<Stack gap="2">
					<Heading
						as="h2"
						size="lg"
						fontFamily={slug ? undefined : "mono"}
						wordBreak="break-all"
					>
						{slug ?? row.id}
					</Heading>
					<Wrap gap="2">
						{row.registry ? (
							<LifecycleBadge status={tenant?.status ?? row.registry.status} />
						) : (
							getAdminConfig().platformApi && (
								<Badge colorPalette="orange" variant="outline">
									no registry row
								</Badge>
							)
						)}
						<OnChainBadge state={row.state} />
						{tenant && (
							<Badge variant="outline">version {tenant.version}</Badge>
						)}
					</Wrap>
				</Stack>
				{tenant && (
					<Wrap gap="2" data-testid="tenant-actions">
						{tenant.status === "active" && (
							<>
								<Button
									size="sm"
									variant="outline"
									onClick={() => setOpen("edit")}
								>
									<LuPencil /> Edit
								</Button>
								<Button
									size="sm"
									variant="outline"
									onClick={() => setOpen("issue-key")}
								>
									<LuKeyRound /> Issue key
								</Button>
								<Button
									size="sm"
									variant="outline"
									colorPalette="orange"
									onClick={() => setOpen("suspend")}
								>
									<LuPause /> Suspend
								</Button>
							</>
						)}
						{tenant.status === "suspended" && (
							<>
								<Button
									size="sm"
									variant="outline"
									onClick={() => setOpen("resume")}
								>
									<LuPlay /> Resume
								</Button>
								<Button
									size="sm"
									variant="outline"
									colorPalette="red"
									onClick={() => setOpen("delete")}
								>
									<LuTrash2 /> Delete
								</Button>
							</>
						)}
					</Wrap>
				)}
			</HStack>

			{record.error && (
				<InlineError
					title="Could not read the tenant"
					error={record.error}
					retry={() => void record.reload()}
					stale={record.detail !== undefined}
				/>
			)}

			<OnChainCard
				client={client}
				tenantId={row.id}
				slug={slug}
				onChain={row.onChain}
				state={row.state}
				status={
					row.registry?.status ?? (registryComplete ? undefined : "unknown")
				}
				ledger={record.detail?.ledger}
			/>

			{slug && !record.detail && !record.error && (
				<HStack py="6" justify="center">
					<Spinner />
				</HStack>
			)}
			{record.detail && tenant && (
				<SimpleGrid columns={{ base: 1, lg: 2 }} gap="4" alignItems="start">
					<RegistryCard detail={record.detail} />
					<Stack gap="4">
						<AdminKeysCard
							detail={record.detail}
							onRevoke={(revoke, label) => setOpen({ revoke, label })}
						/>
						<NotHere />
					</Stack>
				</SimpleGrid>
			)}

			<OtherDeployments others={others} ledger={record.detail?.ledger} />
			{/* Usage is per registry tenant: one with no row has its settlements recorded as unknown. */}
			{row.registry && <TenantUsage tenantId={row.id} />}
			{client && <TenantActivity client={client} tenantId={row.id} />}

			<TenantHistory
				client={client}
				tenantId={row.id}
				slug={slug}
				registry={
					slug
						? {
								entries: record.history,
								error: record.historyError,
								hasOlder: record.next !== null,
								loadingOlder: record.loadingOlder,
								onOlder: () => void record.older(),
								onRetry: () => void record.reload(),
							}
						: undefined
				}
			/>

			{tenant && (
				<>
					<EditTenantDialog
						open={open === "edit"}
						onClose={() => setOpen(undefined)}
						tenant={tenant}
						onSaved={changed}
						onConflict={() => void record.reload()}
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
		</Stack>
	);
}

/**
 * The registry record and its history, read by slug. Nothing is read for a tenant with no slug.
 *
 * The record is re-read with every console refresh, as the ledger moves with the chain. The history
 * is too, but a poll only adds what is new on top: older pages the operator loaded stay. The page is
 * keyed by tenant, so another tenant starts from nothing.
 */
function useTenantRecord(
	slug: string | undefined,
	lastUpdated: Date | undefined,
) {
	const { run } = usePlatform();
	const [detail, setDetail] = useState<TenantDetail>();
	const [error, setError] = useState<string>();
	const [history, setHistory] = useState<HistoryEntry[]>([]);
	const [historyError, setHistoryError] = useState<string>();
	const [next, setNext] = useState<string | null>(null);
	const [loadingOlder, setLoadingOlder] = useState(false);
	// A slow poll can land after a newer one: only the latest read's answer is kept.
	const generation = useRef(0);
	const loaded = useRef<HistoryEntry[]>([]);
	loaded.current = history;
	// Bumped only when a poll replaces the loaded history (page 1 no longer reaches it): an older
	// page asked for before then continues a list that is gone. Any other poll leaves it alone, so
	// an older page still loading when a poll starts is kept.
	const epoch = useRef(0);

	const reload = useCallback(async () => {
		if (!slug) return;
		const current = ++generation.current;
		try {
			const [read, page] = await Promise.all([
				run((api) => api.detail(slug)),
				run((api) => api.history(slug)),
			]);
			if (generation.current !== current || !read || !page) return;
			if (read.ok) {
				setDetail(read.value);
				setError(undefined);
			} else setError(read.error.message);
			if (page.ok) {
				const merged = mergeFirstPage(loaded.current, page.value.entries);
				setHistory(merged.entries);
				if (!merged.keepCursor) {
					epoch.current += 1;
					setNext(page.value.next);
				}
				setHistoryError(undefined);
			} else setHistoryError(page.error.message);
		} catch (cause) {
			// A network error or a non-JSON 502: said on the page, rather than a spinner that never ends.
			if (generation.current !== current) return;
			setError(describeError(cause));
			setHistoryError(describeError(cause));
		}
	}, [run, slug]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: the ledger moves with the chain
	useEffect(() => {
		void reload();
	}, [reload, lastUpdated]);

	const older = async () => {
		if (!slug || !next) return;
		const current = epoch.current;
		setLoadingOlder(true);
		try {
			const page = await run((api) => api.history(slug, next));
			if (epoch.current !== current || !page) return;
			if (page.ok) {
				setHistory((entries) => {
					const known = new Set(entries.map((entry) => entry.id));
					return [
						...entries,
						...page.value.entries.filter((entry) => !known.has(entry.id)),
					];
				});
				setNext(page.value.next);
				setHistoryError(undefined);
			} else setHistoryError(page.error.message);
		} catch (cause) {
			if (epoch.current === current) setHistoryError(describeError(cause));
		} finally {
			setLoadingOlder(false);
		}
	};

	return {
		detail,
		error,
		history,
		historyError,
		next,
		loadingOlder,
		reload,
		older,
	};
}

function RegistryCard({ detail }: { detail: TenantDetail }) {
	const { tenant } = detail;
	return (
		<SectionCard
			title="Registry"
			subtitle="The tenant as wallet-api serves it."
		>
			<DataList.Root orientation="horizontal" size="sm">
				<Item label="Id">
					<Copyable value={tenant.id} label="Tenant id" />
				</Item>
				<Item label="Display name">{tenant.rpName}</Item>
				<Item label="Wallet origin">{tenant.walletOrigin}</Item>
				<Item label="RP ID">{tenant.rpId}</Item>
				<Item label="Expected origins">{list(tenant.expectedOrigins)}</Item>
				<Item label="dApp origins">{list(tenant.allowedDappOrigins)}</Item>
				<Item label="CORS origins">{list(tenant.corsOrigins)}</Item>
				<Item label="Registration">
					{tenant.openRegistration ? "open" : "closed: needs an admin key"}
				</Item>
				<Item label="Users">
					{detail.users} users · {detail.credentials} credentials
				</Item>
				<Item label="Last user operation">
					{detail.lastUseropAt
						? new Date(detail.lastUseropAt).toLocaleString()
						: "none"}
				</Item>
				<Item label="Created">
					{new Date(tenant.createdAt).toLocaleString()}
				</Item>
				{tenant.statusChangedAt && (
					<Item label="Status changed">
						{new Date(tenant.statusChangedAt).toLocaleString()}
					</Item>
				)}
				<Item label="Policy">
					<PolicyView policy={tenant.policy} />
				</Item>
				<Item label="Branding">
					{Object.keys(tenant.branding).length ? (
						<Text
							as="pre"
							fontFamily="mono"
							fontSize="xs"
							whiteSpace="pre-wrap"
						>
							{JSON.stringify(tenant.branding, null, 2)}
						</Text>
					) : (
						"—"
					)}
					<Text fontSize="xs" color="fg.muted">
						Stored, not yet used by any UI.
					</Text>
				</Item>
			</DataList.Root>
		</SectionCard>
	);
}

function AdminKeysCard({
	detail,
	onRevoke,
}: {
	detail: TenantDetail;
	onRevoke: (keyId: string, label: string) => void;
}) {
	return (
		<SectionCard
			title="Admin keys"
			subtitle="By label and hash prefix. A key is shown only once, when it is issued."
		>
			{detail.adminKeys.length === 0 ? (
				<Text fontSize="sm" color="fg.muted">
					None.
				</Text>
			) : (
				<Table.ScrollArea>
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
										{detail.tenant.status !== "deleted" && (
											<Button
												size="xs"
												variant="ghost"
												colorPalette="red"
												onClick={() =>
													onRevoke(key.id, key.label ?? key.hashPrefix)
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
				</Table.ScrollArea>
			)}
		</SectionCard>
	);
}

/** What belongs to the tenant, so an operator does not look for it here. */
function NotHere() {
	return (
		<Box borderWidth="1px" rounded="lg" p="4" bg="bg.subtle">
			<Text fontSize="sm" fontWeight="medium">
				Set by the tenant, not here
			</Text>
			<Text fontSize="sm" color="fg.muted" mt="1">
				Sponsorship rules, transaction display mappings and passkey origins
				belong to the tenant. It sets them with one of its admin keys through
				the admin API (<code>/v1/admin/*</code>).
			</Text>
		</Box>
	);
}

function Item({ label, children }: { label: string; children: ReactNode }) {
	return (
		<DataList.Item>
			<DataList.ItemLabel minW="36">{label}</DataList.ItemLabel>
			<DataList.ItemValue>
				<Box minW="0">{children}</Box>
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
				<Text key={value} fontFamily="mono" fontSize="xs" wordBreak="break-all">
					{value}
				</Text>
			))}
		</Stack>
	);

/** This tenant's last seven days on the selected chain (B4); absent without wallet-api's usage. */
function TenantUsage({ tenantId }: { tenantId: string }) {
	const usage = useUsage();
	if (!usage) return null;
	const mine = usage.tenants.find(
		(tenant) => tenant.tenantId.toLowerCase() === tenantId,
	);
	return (
		<UsageCard
			figures={
				mine ?? {
					decisions: {
						allowed: 0,
						refused: 0,
						refusedBy: { rules: 0, funds: 0, platform: 0, other: 0 },
						byReason: {},
					},
					settled: 0,
					reverted: 0,
					gasWei: "0",
					feeWei: "0",
					overheadWei: "0",
				}
			}
			title="Usage, last 7 days"
			subtitle="This tenant's sponsorship decisions and settlements on this chain, from wallet-api. Refusals are split by whose they are to fix."
		/>
	);
}
