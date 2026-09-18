import type { BlockRange, GianoPaymasterClient, SponsorshipRecord } from '@appliedblockchain/giano-paymaster-sdk';
import { Badge, Button, HStack, Table, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { LuChevronsDown, LuRefreshCw } from 'react-icons/lu';
import { Copyable, SectionCard, notifyError } from '../components/ui';
import { eth, exactEth } from '../lib/format';

/** Rows rendered. Beyond this an operator is reading a database, not a console. */
const MAX_ROWS = 100;

/**
 * Settled sponsorships.
 *
 * Loaded on demand rather than with the overview: this is the one panel backed by a log query, so
 * it is slower than the view calls behind everything else and would otherwise hold up every refresh
 * of the page.
 *
 * **It shows a window of blocks, not all history** (INFRASTRUCTURE §14.6). The read is a single
 * `eth_getLogs` ending at the head, which costs the same on a chain's first day as on its
 * ten-thousandth; reconstructing everything since deployment is hundreds of requests that grow by
 * five a day and eventually stop being servable at all. "Look further back" steps one window into
 * the past and keeps what it finds, so an operator reaches older settlements by asking rather than
 * by everyone paying for them on every load.
 *
 * Gas, fee and overhead are shown separately because they answer different questions — what the
 * network cost, what Giano charged, and what the contract could not observe at settlement.
 */
export function HistoryPanel({ client }: { client: GianoPaymasterClient }) {
  const [records, setRecords] = useState<readonly SponsorshipRecord[]>();
  const [scanned, setScanned] = useState<BlockRange>();
  const [older, setOlder] = useState<BlockRange>();
  const [loading, setLoading] = useState(false);

  // Accumulated across "look further back", so paging never drops what earlier windows found.
  const found = useRef<readonly SponsorshipRecord[]>([]);

  const read = useCallback(
    async (range: BlockRange | undefined, append: boolean) => {
      setLoading(true);
      try {
        const page = await client.getSponsorships({ range });
        found.current = append ? [...page.records, ...found.current] : page.records;
        setRecords(found.current);
        setOlder(page.older);
        setScanned((previous) => (append && previous ? { fromBlock: page.fromBlock, toBlock: previous.toBlock } : page));
      } catch (error) {
        notifyError('Could not load sponsorship history', error);
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  const reload = useCallback(() => {
    found.current = [];
    return read(undefined, false);
  }, [read]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const shown = records ? [...records].reverse().slice(0, MAX_ROWS) : [];
  const blocks = scanned ? `blocks ${scanned.fromBlock}–${scanned.toBlock}` : '';

  return (
    <SectionCard
      title="Sponsorships"
      subtitle="Settlements in the blocks read so far, newest first. A shortfall becomes a recorded deficit rather than a revert — by then the network has already been paid."
      action={
        <HStack gap="2">
          {older && (
            <Button size="sm" variant="outline" onClick={() => void read(older, true)} loading={loading}>
              <LuChevronsDown /> Look further back
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => void reload()} loading={loading}>
            <LuRefreshCw /> Reload
          </Button>
        </HStack>
      }
    >
      {!records && loading && <Text color="fg.muted">Reading logs…</Text>}
      {records && records.length === 0 && (
        <Text color="fg.muted">
          Nothing settled in {blocks}. A settlement older than that is still on chain — "Look further back" reads the preceding window. To make a new one,
          the sample dApp's gasless panel is the quickest way.
        </Text>
      )}
      {shown.length > 0 && (
        <Table.ScrollArea borderWidth="1px" rounded="md" maxH="30rem">
          <Table.Root size="sm" stickyHeader>
            <Table.Header>
              <Table.Row>
                <Table.ColumnHeader>Block</Table.ColumnHeader>
                <Table.ColumnHeader>Tenant</Table.ColumnHeader>
                <Table.ColumnHeader>Sender</Table.ColumnHeader>
                <Table.ColumnHeader></Table.ColumnHeader>
                <Table.ColumnHeader textAlign="end">Gas</Table.ColumnHeader>
                <Table.ColumnHeader textAlign="end">Fee</Table.ColumnHeader>
                <Table.ColumnHeader textAlign="end">Overhead</Table.ColumnHeader>
                <Table.ColumnHeader textAlign="end">Balance after</Table.ColumnHeader>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {shown.map((record) => (
                <Table.Row key={`${record.transactionHash}-${record.userOpHash}`}>
                  <Table.Cell fontFamily="mono" fontSize="xs">
                    {String(record.blockNumber)}
                  </Table.Cell>
                  <Table.Cell>
                    <Copyable value={record.uuid} label="Tenant id" />
                  </Table.Cell>
                  <Table.Cell>
                    <Copyable value={record.sender} label="Sender" />
                  </Table.Cell>
                  <Table.Cell>
                    <Badge colorPalette={record.success ? 'green' : 'red'} variant="subtle" title={record.userOpHash}>
                      {record.success ? 'ok' : 'reverted'}
                    </Badge>
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontFamily="mono" fontSize="xs" title={exactEth(record.gasCostWei)}>
                    {eth(record.gasCostWei, 6)}
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontFamily="mono" fontSize="xs" title={exactEth(record.feeWei)}>
                    {eth(record.feeWei, 6)}
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontFamily="mono" fontSize="xs" title={exactEth(record.overheadWei)}>
                    {eth(record.overheadWei, 6)}
                  </Table.Cell>
                  <Table.Cell textAlign="end" fontFamily="mono" fontSize="xs" title={exactEth(record.newBalanceWei)}>
                    {eth(record.newBalanceWei)}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
        </Table.ScrollArea>
      )}
      {records && (
        <Text fontSize="xs" color="fg.muted" mt="2">
          {records.length > shown.length ? `Showing the most recent ${shown.length} of ${records.length} in ${blocks}. ` : `Read ${blocks}. `}
          {older
            ? 'This is a window of the chain — older settlements exist below it and "Look further back" reads the preceding window.'
            : 'That reaches the first block, so this is every settlement.'}
        </Text>
      )}
    </SectionCard>
  );
}
