import {
	Alert,
	Badge,
	Button,
	Checkbox,
	HStack,
	Input,
	NativeSelect,
	Spinner,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { useMemo, useState } from "react";
import { LuPlus, LuRefreshCw, LuSearch } from "react-icons/lu";
import { InlineError, QueuedMarker } from "../components/status";
import { SectionCard } from "../components/ui";
import { Amount } from "../components/values";
import { getAdminConfig } from "../config";
import { queuedKeys } from "../lib/queued";
import { Link, navigate, tenantPath } from "../lib/router";
import {
	filterTenants,
	nextStep,
	type TenantFilter,
	type TenantRow,
	tenantTotals,
} from "../lib/tenants";
import { LifecycleBadge, OnChainBadge } from "../platform/shared";
import { useConsole } from "../shell/ConsoleContext";
import type { Registry } from "./useRegistry";

const FILTERS: {
	value: TenantFilter;
	label: string;
	registryOnly?: boolean;
}[] = [
	{ value: "all", label: "All" },
	{ value: "active", label: "Active", registryOnly: true },
	{ value: "suspended", label: "Suspended", registryOnly: true },
	{ value: "attention", label: "Needs attention" },
];

/** Where a row links: the slug when the registry has one, else the on-chain id. */
export const rowPath = (row: TenantRow) =>
	tenantPath(row.registry?.slug ?? row.id);

/**
 * One list of tenants (openspec platform-console-tenants): wallet-api's registry joined by id to
 * the selected chain's paymaster roster. A tenant that exists in one and not the other is listed
 * all the same — the registry tenant as *not registered*, the roster entry as having no registry
 * row — because that disagreement is usually the thing worth seeing.
 *
 * Without the platform API there is no registry, and the list is the roster alone, by id.
 */
export function TenantsList({
	rows,
	registry,
	rosterOnChain,
	onCreate,
	onRegister,
}: {
	rows: readonly TenantRow[];
	registry: Registry;
	rosterOnChain: boolean;
	/** Opens Create tenant; only with the platform API. */
	onCreate: () => void;
	/** Opens Register tenant by id; only without the platform API, where there is no create. */
	onRegister: () => void;
}) {
	const { platformApi } = getAdminConfig();
	const { deployment, refresh } = useConsole();
	const [query, setQuery] = useState("");
	const [filter, setFilter] = useState<TenantFilter>("all");
	const [includeDeleted, setIncludeDeleted] = useState(false);

	// Until the registry has been read, a roster entry's missing registry row says nothing: no badge,
	// no footer count, and not a reason to need attention.
	const registryKnown = platformApi && registry.tenants !== undefined;
	const shown = useMemo(
		() => filterTenants(rows, { query, filter, includeDeleted, registryKnown }),
		[rows, query, filter, includeDeleted, registryKnown],
	);
	const totals = useMemo(() => tenantTotals(rows), [rows]);
	const deletedCount = rows.filter(
		(row) => row.registry?.status === "deleted",
	).length;
	const live = rows.filter((row) => row.registry?.status !== "deleted").length;

	const refreshAll = () => Promise.all([registry.reload(), refresh()]);

	return (
		<SectionCard
			title={`Tenants (${live})`}
			subtitle={
				platformApi
					? `wallet-api's tenants, with their state on the ${deployment.name} paymaster (chain ${deployment.chainId}). Registry changes take effect on the next request; nothing is redeployed.`
					: `The ${deployment.name} paymaster's roster (chain ${deployment.chainId}), read from the chain. This console has no platform API, so tenants are listed by id.`
			}
			action={
				<HStack>
					<Button
						size="sm"
						variant="ghost"
						onClick={() => void refreshAll()}
						loading={registry.loading}
						aria-label="Refresh tenants"
					>
						<LuRefreshCw />
					</Button>
					{platformApi ? (
						<Button size="sm" colorPalette="brand" onClick={onCreate}>
							<LuPlus /> Create tenant
						</Button>
					) : (
						<Button size="sm" colorPalette="brand" onClick={onRegister}>
							<LuPlus /> Register tenant
						</Button>
					)}
				</HStack>
			}
		>
			<Stack gap="3">
				{registry.error && (
					<InlineError
						title="Could not read the tenant registry"
						error={registry.error}
						retry={() => void registry.reload()}
						retrying={registry.loading}
						stale={registry.tenants !== undefined}
					/>
				)}
				{!registry.error && registry.deletedError && (
					<Alert.Root status="warning" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Title>Could not read the deleted tenants</Alert.Title>
							<Alert.Description overflowWrap="anywhere">
								{registry.deletedError} The list has the live tenants only.
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}
				{!rosterOnChain && (
					<Alert.Root status="info" size="sm">
						<Alert.Indicator />
						<Alert.Content>
							<Alert.Description overflowWrap="anywhere">
								This paymaster predates the on-chain roster, so its tenants were
								read from registration logs, one window at a time. A tenant
								registered before that window is missing from the list.
							</Alert.Description>
						</Alert.Content>
					</Alert.Root>
				)}

				<HStack gap="3" flexWrap="wrap">
					<HStack flex="1" minW="56" gap="2">
						<LuSearch aria-hidden="true" />
						<Input
							size="sm"
							value={query}
							onChange={(event) => setQuery(event.target.value)}
							placeholder={
								platformApi ? "Search slug, name, id or origin" : "Search by id"
							}
							aria-label="Search tenants"
						/>
					</HStack>
					<NativeSelect.Root size="sm" width="auto">
						<NativeSelect.Field
							aria-label="Show"
							value={filter}
							onChange={(event) =>
								setFilter(event.currentTarget.value as TenantFilter)
							}
						>
							{FILTERS.filter(
								(option) => platformApi || !option.registryOnly,
							).map((option) => (
								<option key={option.value} value={option.value}>
									{option.label}
								</option>
							))}
						</NativeSelect.Field>
						<NativeSelect.Indicator />
					</NativeSelect.Root>
					{platformApi && (
						<Checkbox.Root
							size="sm"
							checked={includeDeleted}
							onCheckedChange={(event) =>
								setIncludeDeleted(event.checked === true)
							}
						>
							<Checkbox.HiddenInput />
							<Checkbox.Control />
							<Checkbox.Label>
								Show deleted tenants ({deletedCount})
							</Checkbox.Label>
						</Checkbox.Root>
					)}
				</HStack>

				{platformApi && registry.tenants === undefined && registry.loading ? (
					<HStack py="8" justify="center">
						<Spinner />
					</HStack>
				) : (
					<Table.ScrollArea borderWidth="1px" rounded="md">
						<Table.Root size="sm" interactive stickyHeader>
							<Table.Header>
								<Table.Row>
									<Table.ColumnHeader>Tenant</Table.ColumnHeader>
									{platformApi && (
										<Table.ColumnHeader>Status</Table.ColumnHeader>
									)}
									<Table.ColumnHeader>
										On chain {deployment.chainId}
									</Table.ColumnHeader>
									<Table.ColumnHeader textAlign="end">
										Balance
									</Table.ColumnHeader>
									<Table.ColumnHeader textAlign="end">
										Deficit
									</Table.ColumnHeader>
									<Table.ColumnHeader textAlign="end">Fee</Table.ColumnHeader>
									{platformApi && (
										<Table.ColumnHeader textAlign="end">
											Users
										</Table.ColumnHeader>
									)}
									<Table.ColumnHeader>Next</Table.ColumnHeader>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{shown.map((row) => (
									<Row
										key={row.id}
										row={row}
										platformApi={platformApi}
										registryKnown={registryKnown}
									/>
								))}
								{shown.length === 0 && (
									<Table.Row>
										<Table.Cell colSpan={platformApi ? 8 : 6}>
											<Text color="fg.muted">
												{rows.length === 0
													? "No tenants yet. A deployment is not complete until one is registered and funded."
													: "No tenant matches."}
											</Text>
										</Table.Cell>
									</Table.Row>
								)}
							</Table.Body>
						</Table.Root>
					</Table.ScrollArea>
				)}

				<Text fontSize="sm" color="fg.muted" data-testid="tenant-totals">
					On {deployment.name}: <Amount wei={totals.held} /> held for{" "}
					{totals.onChain} tenant{totals.onChain === 1 ? "" : "s"}
					{totals.deficit > 0n && (
						<>
							, <Amount wei={totals.deficit} /> in deficit
						</>
					)}
					.
					{registryKnown &&
						(totals.unregistered > 0
							? ` ${totals.unregistered} on-chain tenant${totals.unregistered === 1 ? " has" : "s have"} no registry row.`
							: " Every on-chain tenant has a registry row.")}
				</Text>
			</Stack>
		</SectionCard>
	);
}

function Row({
	row,
	platformApi,
	registryKnown,
}: {
	row: TenantRow;
	platformApi: boolean;
	registryKnown: boolean;
}) {
	const { registry, onChain } = row;
	const step = nextStep(row);
	const path = rowPath(row);
	return (
		<Table.Row
			cursor="pointer"
			onClick={() => navigate(path)}
			data-testid={`tenant-row-${registry?.slug ?? row.id}`}
		>
			<Table.Cell>
				<Link
					to={path}
					fontWeight="medium"
					fontFamily={registry ? undefined : "mono"}
					fontSize={registry ? undefined : "xs"}
					onClick={(event) => event.stopPropagation()}
				>
					{registry?.slug ?? row.id}
				</Link>
				{registry ? (
					<Text fontSize="xs" color="fg.muted">
						{registry.rpName} · {registry.walletOrigin}
					</Text>
				) : (
					registryKnown && (
						<Badge
							size="sm"
							colorPalette="orange"
							variant="outline"
							data-testid="roster-only"
						>
							no registry row
						</Badge>
					)
				)}
			</Table.Cell>
			{platformApi && (
				<Table.Cell>
					{registry ? <LifecycleBadge status={registry.status} /> : "—"}
				</Table.Cell>
			)}
			<Table.Cell>
				<OnChainBadge state={row.state} />
			</Table.Cell>
			<Table.Cell textAlign="end" onClick={(event) => event.stopPropagation()}>
				{onChain ? <Amount wei={onChain.balance} /> : "—"}
			</Table.Cell>
			<Table.Cell
				textAlign="end"
				color={onChain && onChain.deficit > 0n ? "red.fg" : undefined}
				onClick={(event) => event.stopPropagation()}
			>
				{onChain ? <Amount wei={onChain.deficit} /> : "—"}
			</Table.Cell>
			<Table.Cell textAlign="end" onClick={(event) => event.stopPropagation()}>
				{onChain ? (
					onChain.hasFeeOverride ? (
						<Stack gap="0" align="flex-end">
							<Amount wei={onChain.effectiveFeeWei} decimals={6} />
							<Text fontSize="xs" color="brand.fg">
								override
							</Text>
						</Stack>
					) : (
						<Text as="span" color="fg.muted">
							default
						</Text>
					)
				) : (
					"—"
				)}
			</Table.Cell>
			{platformApi && (
				<Table.Cell textAlign="end">{registry?.users ?? "—"}</Table.Cell>
			)}
			<Table.Cell onClick={(event) => event.stopPropagation()}>
				<Stack gap="1">
					{step && (
						<Link to={path} fontSize="sm" color="brand.fg" fontWeight="medium">
							{step === "register" ? "Register on chain" : "Fund"}
						</Link>
					)}
					{onChain && (
						<QueuedMarker
							keys={[
								queuedKeys.tenantFee(onChain.id),
								queuedKeys.tenantWithdraw(onChain.id),
							]}
						/>
					)}
				</Stack>
			</Table.Cell>
		</Table.Row>
	);
}
