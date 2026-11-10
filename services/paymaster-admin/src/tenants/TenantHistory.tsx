import type { GianoPaymasterClient } from "@appliedblockchain/giano-paymaster-sdk";
import {
	Badge,
	Box,
	Button,
	Heading,
	HStack,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { useCallback } from "react";
import { LuChevronsDown } from "react-icons/lu";
import {
	AdminEventList,
	useAdminEvents,
	useNamer,
} from "../components/admin-events";
import { InlineError } from "../components/status";
import { SectionCard } from "../components/ui";
import type { HistoryEntry } from "../lib/platform-api";
import { historyChanges } from "../lib/tenants";
import { actorLabel } from "../platform/shared";
import { useConsole } from "../shell/ConsoleContext";

type RegistryHistory = {
	entries: readonly HistoryEntry[];
	error: string | undefined;
	hasOlder: boolean;
	loadingOlder: boolean;
	onOlder: () => void;
	onRetry: () => void;
};

/**
 * The tenant's history, newest first: in the registry (openspec K10), who did what, when, and for
 * an edit the value of each field before and after; on this chain (B1), its admin events — its
 * registration, funding, withdrawals, enabled state, fee and withdrawal address, and the timelock
 * calls that change them. The two are paged separately, a cursor and a window of blocks, so they
 * are listed apart rather than interleaved at boundaries neither knows.
 */
export function TenantHistory({
	registry,
	client,
	tenantId,
	slug,
}: {
	/** Absent for a tenant the registry does not know. */
	registry?: RegistryHistory;
	/** Undefined while the paymaster has not been read; the registry half still shows. */
	client: GianoPaymasterClient | undefined;
	tenantId: string;
	slug: string | undefined;
}) {
	const { deployment } = useConsole();
	return (
		<SectionCard
			title="History"
			subtitle={
				registry
					? `Every change to this tenant, newest first: in the registry, and on ${deployment.name}.`
					: `Every change to this tenant on ${deployment.name}, newest first.`
			}
		>
			<Stack gap="5">
				{registry && (
					<Stack gap="2">
						<Heading size="xs" color="fg.muted">
							In the registry
						</Heading>
						<RegistryEntries {...registry} />
					</Stack>
				)}
				<Stack gap="2">
					{registry && (
						<Heading size="xs" color="fg.muted">
							On {deployment.name}
						</Heading>
					)}
					{client ? (
						<ChainEvents client={client} tenantId={tenantId} slug={slug} />
					) : (
						<Text fontSize="sm" color="fg.muted">
							The paymaster has not been read yet.
						</Text>
					)}
				</Stack>
			</Stack>
		</SectionCard>
	);
}

function ChainEvents({
	client,
	tenantId,
	slug,
}: {
	client: GianoPaymasterClient;
	tenantId: string;
	slug: string | undefined;
}) {
	const { lastUpdated } = useConsole();
	const events = useAdminEvents(client, lastUpdated, tenantId);
	const namer = useNamer(
		useCallback((uuid: string) => slug ?? `tenant ${uuid}`, [slug]),
	);
	return (
		<Stack gap="2" data-testid="tenant-chain-history">
			{events.error && (
				<InlineError
					title="Could not read this tenant's events"
					error={events.error}
					retry={() => void events.refresh()}
					retrying={events.loading}
					stale={events.range !== undefined}
				/>
			)}
			{!events.settled ? (
				<Text fontSize="sm" color="fg.muted">
					Reading the chain…
				</Text>
			) : events.items.length === 0 ? (
				!events.error && (
					<Text fontSize="sm" color="fg.muted">
						Nothing in blocks {events.range?.fromBlock.toString()}–
						{events.range?.toBlock.toString()}.
					</Text>
				)
			) : (
				<AdminEventList events={events.items} namer={namer} />
			)}
			{events.olderError && (
				<InlineError
					title="Could not read the older window"
					error={events.olderError}
					retry={() => void events.lookFurther()}
					retrying={events.olderLoading}
				/>
			)}
			{events.older ? (
				<Button
					size="xs"
					variant="ghost"
					alignSelf="flex-start"
					loading={events.olderLoading}
					onClick={() => void events.lookFurther()}
				>
					<LuChevronsDown /> Look further back
				</Button>
			) : (
				// Only once a window has been read: after a failed first read it would be false.
				events.range && (
					<Text fontSize="xs" color="fg.muted">
						That reaches the first block: this is every on-chain change to this
						tenant.
					</Text>
				)
			)}
		</Stack>
	);
}

function RegistryEntries({
	entries,
	error,
	hasOlder,
	loadingOlder,
	onOlder,
	onRetry,
}: RegistryHistory) {
	return (
		<Stack gap="3" data-testid="tenant-history">
			{error && (
				<InlineError
					title="Could not read the history"
					error={error}
					retry={onRetry}
					stale={entries.length > 0}
				/>
			)}
			{entries.map((entry) => (
				<Entry key={entry.id} entry={entry} />
			))}
			{entries.length === 0 && !error && (
				<Text fontSize="sm" color="fg.muted">
					No history.
				</Text>
			)}
			{hasOlder && (
				<Button
					size="xs"
					variant="ghost"
					alignSelf="flex-start"
					loading={loadingOlder}
					onClick={onOlder}
				>
					Older entries
				</Button>
			)}
		</Stack>
	);
}

function Entry({ entry }: { entry: HistoryEntry }) {
	const changes =
		entry.action === "update" ? historyChanges(entry.before, entry.after) : [];
	const reason =
		typeof entry.detail?.reason === "string" ? entry.detail.reason : undefined;
	const key =
		typeof entry.detail?.label === "string"
			? entry.detail.label
			: typeof entry.detail?.hashPrefix === "string"
				? `${entry.detail.hashPrefix}…`
				: undefined;
	return (
		<Box borderBottomWidth="1px" pb="3">
			<HStack gap="3" align="flex-start" flexWrap="wrap">
				<Badge variant="subtle" minW="28" justifyContent="center">
					{entry.action}
				</Badge>
				<Box>
					<Text fontSize="sm">
						{actorLabel(entry.actor)}
						{reason && ` · “${reason}”`}
						{key && ` · key ${key}`}
					</Text>
					<Text fontSize="xs" color="fg.muted">
						{new Date(entry.createdAt).toLocaleString()}
					</Text>
				</Box>
			</HStack>
			{changes.length > 0 && (
				<Table.ScrollArea mt="2">
					<Table.Root size="sm" variant="outline">
						<Table.Header>
							<Table.Row>
								<Table.ColumnHeader>Field</Table.ColumnHeader>
								<Table.ColumnHeader>Before</Table.ColumnHeader>
								<Table.ColumnHeader>After</Table.ColumnHeader>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{changes.map((change) => (
								<Table.Row key={change.field}>
									<Table.Cell fontSize="xs">{change.field}</Table.Cell>
									<Value value={change.before} />
									<Value value={change.after} />
								</Table.Row>
							))}
						</Table.Body>
					</Table.Root>
				</Table.ScrollArea>
			)}
		</Box>
	);
}

function Value({ value }: { value: unknown }) {
	return (
		<Table.Cell
			fontFamily="mono"
			fontSize="xs"
			whiteSpace="pre-wrap"
			wordBreak="break-all"
		>
			{value === undefined
				? "—"
				: typeof value === "string"
					? value
					: JSON.stringify(value, null, 1)}
		</Table.Cell>
	);
}
