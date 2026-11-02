import type {
	BlockRange,
	GianoPaymasterClient,
	SponsorshipRecord,
} from "@appliedblockchain/giano-paymaster-sdk";
import { Badge, Button, Stack, Table, Text } from "@chakra-ui/react";
import { useCallback, useEffect, useState } from "react";
import { LuChevronsDown } from "react-icons/lu";
import { InlineError } from "../components/status";
import { Copyable, SectionCard } from "../components/ui";
import { Amount, TxLink } from "../components/values";
import { describeError } from "../lib/format";

/**
 * One tenant's settled sponsorships on the selected chain (openspec N8), newest first.
 *
 * A window of blocks at a time, like the Activity tab, but filtered by the node on the indexed
 * tenant topic, so going further back for one tenant stays cheap.
 */
export function TenantActivity({
	client,
	tenantId,
}: {
	client: GianoPaymasterClient;
	tenantId: string;
}) {
	const [records, setRecords] = useState<readonly SponsorshipRecord[]>();
	const [range, setRange] = useState<BlockRange>();
	const [older, setOlder] = useState<BlockRange>();
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();

	const read = useCallback(
		async (window: BlockRange | undefined) => {
			setLoading(true);
			try {
				const page = await client.getSponsorships({ tenantId, range: window });
				// Within a window the SDK returns settlements oldest first.
				const newest = [...page.records].reverse();
				setRecords((existing) =>
					window && existing ? [...existing, ...newest] : newest,
				);
				setRange((existing) => ({
					fromBlock: page.fromBlock,
					toBlock: window && existing ? existing.toBlock : page.toBlock,
				}));
				setOlder(page.older);
				setError(undefined);
			} catch (cause) {
				setError(describeError(cause));
			} finally {
				setLoading(false);
			}
		},
		[client, tenantId],
	);

	useEffect(() => {
		void read(undefined);
	}, [read]);

	return (
		<SectionCard
			title="Recent sponsorships"
			subtitle={
				range
					? `Settled for this tenant in blocks ${range.fromBlock}–${range.toBlock}, newest first.`
					: "Settled for this tenant on this chain, newest first."
			}
		>
			<Stack gap="3">
				{error && (
					<InlineError
						title="Could not read the sponsorships"
						error={error}
						retry={() => void read(undefined)}
						retrying={loading}
						stale={records !== undefined}
					/>
				)}
				{records && records.length === 0 && (
					<Text fontSize="sm" color="fg.muted">
						None in these blocks.
					</Text>
				)}
				{records && records.length > 0 && (
					<Table.ScrollArea borderWidth="1px" rounded="md">
						<Table.Root size="sm">
							<Table.Header>
								<Table.Row>
									<Table.ColumnHeader>Block</Table.ColumnHeader>
									<Table.ColumnHeader>Account</Table.ColumnHeader>
									<Table.ColumnHeader textAlign="end">Gas</Table.ColumnHeader>
									<Table.ColumnHeader textAlign="end">Fee</Table.ColumnHeader>
									<Table.ColumnHeader>Result</Table.ColumnHeader>
									<Table.ColumnHeader>Transaction</Table.ColumnHeader>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{records.map((record) => (
									<Table.Row
										key={`${record.transactionHash}:${record.userOpHash}`}
									>
										<Table.Cell fontFamily="mono" fontSize="xs">
											{record.blockNumber.toString()}
										</Table.Cell>
										<Table.Cell>
											<Copyable value={record.sender} label="Account" />
										</Table.Cell>
										<Table.Cell textAlign="end">
											<Amount wei={record.gasCostWei} decimals={6} />
										</Table.Cell>
										<Table.Cell textAlign="end">
											<Amount wei={record.feeWei} decimals={6} />
										</Table.Cell>
										<Table.Cell>
											<Badge
												colorPalette={record.success ? "green" : "orange"}
												variant="subtle"
											>
												{record.success ? "succeeded" : "reverted, gas charged"}
											</Badge>
										</Table.Cell>
										<Table.Cell>
											<TxLink hash={record.transactionHash} />
										</Table.Cell>
									</Table.Row>
								))}
							</Table.Body>
						</Table.Root>
					</Table.ScrollArea>
				)}
				{older && (
					<Button
						size="xs"
						variant="ghost"
						alignSelf="flex-start"
						loading={loading}
						onClick={() => void read(older)}
					>
						<LuChevronsDown /> Look further back
					</Button>
				)}
			</Stack>
		</SectionCard>
	);
}
