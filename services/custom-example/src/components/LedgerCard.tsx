import { Box, Button, HStack, SegmentGroup, Stack, Table, Text } from '@chakra-ui/react';
import { Fragment, useMemo, useState } from 'react';
import { LuDownload, LuTrash2 } from 'react-icons/lu';
import { CONNECTOR_VERSION } from '../config';
import { formatDuration, formatTime, shortHex, toJson } from '../lib/format';
import { exportLedger, LEDGER_CAP, type LedgerEntry } from '../lib/ledger';
import { useDemo } from '../state/store';
import { EntryDetails, EntryStatusText, Mono, SectionCard } from './primitives';
import { ClipboardButton, ClipboardRoot } from './ui/clipboard';

type Filter = 'all' | 'failed' | 'refused' | 'violations';

const matches = (entry: LedgerEntry, filter: Filter) =>
  filter === 'all' ? true : filter === 'failed' ? entry.status === 'failed' || entry.status === 'timed-out' : filter === 'refused' ? entry.status === 'refused' : entry.status === 'violation';

/** R9: every outcome, in order, with its evidence. Persists across reloads; nothing leaves except by Clear. */
export function LedgerCard() {
  const { state, config, clearLedger } = useDemo();
  const [filter, setFilter] = useState<Filter>('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const entries = useMemo(() => state.ledger.entries.filter((entry) => matches(entry, filter)), [state.ledger.entries, filter]);
  const counts = useMemo(
    () => ({
      all: state.ledger.entries.length,
      failed: state.ledger.entries.filter((entry) => matches(entry, 'failed')).length,
      refused: state.ledger.entries.filter((entry) => matches(entry, 'refused')).length,
      violations: state.ledger.entries.filter((entry) => matches(entry, 'violations')).length,
    }),
    [state.ledger.entries],
  );
  const exported = useMemo(
    () => exportLedger(state.ledger, { config, connectorVersion: CONNECTOR_VERSION, userAgent: navigator.userAgent, dappOrigin: window.location.origin }),
    [state.ledger, config],
  );

  return (
    <SectionCard
      id="ledger"
      title="Ledger"
      description="Every action, in order, with its evidence. Persists across reloads; nothing leaves this list except by Clear."
      aside={
        <HStack>
          <ClipboardRoot value={exported}>
            <ClipboardButton size="sm" variant="outline" data-testid="ledger-export">
              <LuDownload /> Export JSON
            </ClipboardButton>
          </ClipboardRoot>
          <Button size="sm" variant="outline" colorPalette="red" onClick={clearLedger} disabled={!state.ledger.entries.length}>
            <LuTrash2 /> Clear
          </Button>
        </HStack>
      }
    >
      <SegmentGroup.Root size="sm" value={filter} onValueChange={(details) => details.value && setFilter(details.value as Filter)}>
        <SegmentGroup.Indicator />
        <SegmentGroup.Items
          items={[
            { value: 'all', label: `All ${counts.all}` },
            { value: 'failed', label: `Failed ${counts.failed}` },
            { value: 'refused', label: `Refused ${counts.refused}` },
            { value: 'violations', label: `Violations ${counts.violations}` },
          ]}
        />
      </SegmentGroup.Root>

      {state.ledger.evicted > 0 && (
        <Text fontSize="xs" color="orange.fg">
          The ledger is capped at {LEDGER_CAP} entries; {state.ledger.evicted} oldest entries were evicted. Export before that matters.
        </Text>
      )}

      {entries.length === 0 ? (
        <Text fontSize="sm" color="fg.muted">
          Nothing recorded yet. Every action on this page appends a row here.
        </Text>
      ) : (
        <Box overflowX="auto">
          <Table.Root size="sm" variant="line" interactive data-testid="ledger-table">
            <Table.Header>
              <Table.Row>
                <Table.ColumnHeader>Time</Table.ColumnHeader>
                <Table.ColumnHeader>Section</Table.ColumnHeader>
                <Table.ColumnHeader>Method</Table.ColumnHeader>
                <Table.ColumnHeader>Chain</Table.ColumnHeader>
                <Table.ColumnHeader>Payer</Table.ColumnHeader>
                <Table.ColumnHeader>Status</Table.ColumnHeader>
                <Table.ColumnHeader>Hash</Table.ColumnHeader>
                <Table.ColumnHeader textAlign="end">Took</Table.ColumnHeader>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {entries.map((entry) => (
                <Fragment key={entry.id}>
                  <Table.Row onClick={() => setExpanded((current) => (current === entry.id ? null : entry.id))} cursor="pointer" data-testid="ledger-row" data-status={entry.status}>
                    <Table.Cell whiteSpace="nowrap">
                      <Mono muted>{formatTime(entry.at)}</Mono>
                    </Table.Cell>
                    <Table.Cell>{entry.section}</Table.Cell>
                    <Table.Cell>
                      <Stack gap="0">
                        <Text fontSize="sm">{entry.label}</Text>
                        <Mono muted>{entry.method}</Mono>
                      </Stack>
                    </Table.Cell>
                    <Table.Cell>
                      <Mono>{entry.chainId}</Mono>
                    </Table.Cell>
                    <Table.Cell>
                      <Mono muted>{entry.attribution?.actualPayer ?? entry.declaredPayer ?? '—'}</Mono>
                    </Table.Cell>
                    <Table.Cell>
                      <EntryStatusText entry={entry} />
                    </Table.Cell>
                    <Table.Cell>
                      <Mono muted>{entry.userOpHash ? shortHex(entry.userOpHash) : '—'}</Mono>
                    </Table.Cell>
                    <Table.Cell textAlign="end">
                      <Mono muted>{formatDuration(entry.durationMs)}</Mono>
                    </Table.Cell>
                  </Table.Row>
                  {expanded === entry.id && (
                    <Table.Row>
                      <Table.Cell colSpan={8} bg="bg.subtle">
                        <EntryDetails entry={entry} />
                      </Table.Cell>
                    </Table.Row>
                  )}
                </Fragment>
              ))}
            </Table.Body>
          </Table.Root>
        </Box>
      )}
      <Text fontSize="xs" color="fg.muted">
        Export includes the runtime configuration, the connector version and the user agent, so an entry is reportable as-is. {toJson(config.chains.map((chain) => chain.chainId), 0)}
      </Text>
    </SectionCard>
  );
}

export function EventsCard() {
  const { state } = useDemo();
  return (
    <SectionCard id="events" title="Provider events" description="What the provider emitted, as it emitted it." sdk={[['provider.on(event, listener)', 'connect, accountsChanged, chainChanged and disconnect, per chain']]}>
      {state.ledger.events.length === 0 ? (
        <Text fontSize="sm" color="fg.muted">
          No events yet. connect, accountsChanged, chainChanged and disconnect land here.
        </Text>
      ) : (
        <Stack gap="1" data-testid="events">
          {state.ledger.events.slice(0, 50).map((event) => (
            <HStack key={event.id} gap="3" flexWrap="wrap">
              <Mono muted>{formatTime(event.at)}</Mono>
              <Mono muted>{event.chainId}</Mono>
              <Text fontSize="sm" fontWeight="medium">
                {event.event}
              </Text>
              <Mono>{toJson(event.payload, 0)}</Mono>
            </HStack>
          ))}
        </Stack>
      )}
    </SectionCard>
  );
}
