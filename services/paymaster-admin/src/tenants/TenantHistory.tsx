import {
	Badge,
	Box,
	Button,
	HStack,
	Stack,
	Table,
	Text,
} from "@chakra-ui/react";
import { InlineError } from "../components/status";
import { SectionCard } from "../components/ui";
import type { HistoryEntry } from "../lib/platform-api";
import { historyChanges } from "../lib/tenants";
import { actorLabel } from "../platform/shared";

/**
 * The tenant's history (openspec K10), newest first: who did what, when, and for an edit the value
 * of each field before and after. A create lists what it set; a key issue or revoke names the key.
 */
export function TenantHistory({
	entries,
	error,
	hasOlder,
	loadingOlder,
	onOlder,
	onRetry,
}: {
	entries: readonly HistoryEntry[];
	error: string | undefined;
	hasOlder: boolean;
	loadingOlder: boolean;
	onOlder: () => void;
	onRetry: () => void;
}) {
	return (
		<SectionCard
			title="History"
			subtitle="Every change to this tenant, newest first."
		>
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
		</SectionCard>
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
