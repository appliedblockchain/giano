import type { BlockRange, GianoPaymasterClient, SponsorshipRecord } from '@appliedblockchain/giano-paymaster-sdk';
import { Badge, Button, HStack, Table, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { LuChevronsDown, LuRefreshCw } from 'react-icons/lu';
import { Copyable, SectionCard, notifyError } from '../components/ui';
import { eth, exactEth } from '../lib/format';

/**
 * Rows rendered from each window read.
 *
 * Per window rather than across all of them, because a shared budget is one a busy window can spend
 * by itself: settlements are shown newest first, so the newest window's rows come first, and if it
 * has more than the budget allows then "look further back" loads an older window whose rows are all
 * past the cut. The button would appear to do nothing. Budgeting each window separately means every
 * window an operator asks for can put rows on the table.
 */
const ROWS_PER_WINDOW = 100;

/** One window's worth of settlements, kept separate so each gets its own share of the table. */
type Loaded = BlockRange & { records: readonly SponsorshipRecord[] };

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
  /** Newest window first, which is also the order they are rendered in. */
  const [loaded, setLoaded] = useState<readonly Loaded[]>();
  const [older, setOlder] = useState<BlockRange>();
  const [loading, setLoading] = useState(false);

  const read = useCallback(
    async (range: BlockRange | undefined, append: boolean) => {
      setLoading(true);
      try {
        const { fromBlock, toBlock, older: previous, records } = await client.getSponsorships({ range });
        const window = { fromBlock, toBlock, records };
        setLoaded((existing) => (append && existing ? [...existing, window] : [window]));
        setOlder(previous);
      } catch (error) {
        notifyError('Could not load sponsorship history', error);
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  const reload = useCallback(() => read(undefined, false), [read]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Each window contributes its own newest rows, so asking for an older one always adds to the
  // table. Within a window the SDK returns settlements newest last, hence the reverse.
  const shown = useMemo(() => (loaded ?? []).flatMap((window) => [...window.records].reverse().slice(0, ROWS_PER_WINDOW)), [loaded]);
  const total = (loaded ?? []).reduce((sum, window) => sum + window.records.length, 0);
  const blocks = loaded?.length ? `blocks ${loaded[loaded.length - 1].fromBlock}–${loaded[0].toBlock}` : '';

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
      {!loaded && loading && <Text color="fg.muted">Reading logs…</Text>}
      {loaded && total === 0 && (
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
      {loaded && (
        <Text fontSize="xs" color="fg.muted" mt="2">
          {total > shown.length ? `Showing ${shown.length} of ${total} settlements in ${blocks}. ` : `Read ${blocks}. `}
          {older
            ? 'This is a window of the chain — older settlements exist below it and "Look further back" reads the preceding window.'
            : 'That reaches the first block, so this is every settlement.'}
        </Text>
      )}
    </SectionCard>
  );
}
