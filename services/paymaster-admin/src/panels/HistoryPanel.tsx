import type { GianoPaymasterClient, SponsorshipRecord } from '@appliedblockchain/giano-paymaster-sdk';
import { Badge, Button, Table, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useState } from 'react';
import { LuRefreshCw } from 'react-icons/lu';
import { Copyable, SectionCard, notifyError } from '../components/ui';
import { eth, exactEth } from '../lib/format';

/**
 * Settled sponsorships.
 *
 * Loaded on demand rather than with the overview: this is a log query over the chain's whole
 * history, which is much slower than the view calls behind everything else and would otherwise
 * hold up every refresh of the page.
 *
 * Gas, fee and overhead are shown separately because they answer different questions — what the
 * network cost, what Giano charged, and what the contract could not observe at settlement.
 */
export function HistoryPanel({ client }: { client: GianoPaymasterClient }) {
  const [records, setRecords] = useState<readonly SponsorshipRecord[]>();
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRecords(await client.getSponsorships());
    } catch (error) {
      notifyError('Could not load sponsorship history', error);
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const shown = records ? [...records].reverse().slice(0, 100) : [];

  return (
    <SectionCard
      title="Sponsorships"
      subtitle="Every settlement, newest first. A shortfall becomes a recorded deficit rather than a revert — by then the network has already been paid."
      action={
        <Button size="sm" variant="outline" onClick={() => void load()} loading={loading}>
          <LuRefreshCw /> Reload
        </Button>
      }
    >
      {!records && loading && <Text color="fg.muted">Reading logs…</Text>}
      {records && records.length === 0 && (
        <Text color="fg.muted">
          Nothing settled on this chain yet. Send a sponsored operation and reload — the sample dApp's gasless panel is the quickest way.
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
      {records && records.length > shown.length && (
        <Text fontSize="xs" color="fg.muted" mt="2">
          Showing the most recent {shown.length} of {records.length}.
        </Text>
      )}
    </SectionCard>
  );
}
