import { Box, Button, HStack, Link, Stack, Table, Text } from '@chakra-ui/react';
import { useTabNav } from '../state/tabs';
import { LuRefreshCw } from 'react-icons/lu';
import { formatDuration } from '../lib/format';
import { summarise, type CheckState } from '../lib/preflight';
import { useDemo } from '../state/store';
import { Mono, SectionCard, StatusText, type Tone } from './primitives';

const TONE: Record<CheckState, Tone> = { pass: 'green', warn: 'orange', fail: 'red', running: 'gray' };

/** The one-line verdict under the header; the card holds the rows (design.md D14). */
export function PreflightLine() {
  const { state } = useDemo();
  const { go } = useTabNav();
  const result = state.preflight;
  if (!result) {
    return (
      <Box px={{ base: 4, md: 12 }} py="2" borderBottomWidth="1px" bg="bg.subtle">
        <StatusText tone="gray" busy>
          Checking setup…
        </StatusText>
      </Box>
    );
  }
  const summary = summarise(result);
  return (
    <Box px={{ base: 4, md: 12 }} py="2" borderBottomWidth="1px" bg="bg.subtle" data-testid="preflight-line" data-state={summary.state}>
      <HStack gap="3" flexWrap="wrap">
        {summary.state === 'pass' ? (
          <>
            <StatusText tone="green">Setup verified</StatusText>
            <Mono muted>
              {result.checks.length} checks · {formatDuration(result.durationMs)}
            </Mono>
          </>
        ) : (
          <>
            <StatusText tone={TONE[summary.state]}>
              {summary.fails.length ? `${summary.fails.length} setup problem${summary.fails.length > 1 ? 's' : ''}` : `${summary.warns.length} warning${summary.warns.length > 1 ? 's' : ''}`}
            </StatusText>
            <Text fontSize="sm" color={summary.fails.length ? 'red.fg' : 'orange.fg'}>
              {[...summary.fails, ...summary.warns].map((check) => check.title).join(' · ')}
            </Text>
          </>
        )}
        <Link as="button" fontSize="sm" fontWeight="medium" ml="auto" onClick={() => go('setup')}>
          {summary.state === 'pass' ? 'Details' : 'Fix these first'}
        </Link>
      </HStack>
    </Box>
  );
}

export function PreflightCard() {
  const { state, rerunPreflight } = useDemo();
  const result = state.preflight;
  return (
    <SectionCard
      id="preflight"
      title="Setup checks"
      description="Six checks that answer in under a second what a 15 s handshake timeout or a 120 s receipt timeout would otherwise answer. Nothing here blocks the page; a failed row disables or warns on the controls it invalidates."
      sdk={[
        ['GET {walletUrl}/api/v1/version', 'the wallet origin\'s public version endpoint — reachability, CORS for this origin, wallet-api version'],
        ['publicClient.getChainId / getCode', 'viem reads against each configured RPC — no wallet involved'],
      ]}
      aside={
        <Button size="sm" variant="outline" onClick={() => void rerunPreflight()} loading={state.preflightRunning} loadingText="Running…">
          <LuRefreshCw /> Re-run checks
        </Button>
      }
    >
      {!result ? (
        <StatusText tone="gray" busy>
          Running…
        </StatusText>
      ) : (
        <Stack gap="3">
          <Table.Root size="sm" variant="line">
            <Table.Header>
              <Table.Row>
                <Table.ColumnHeader w="28">State</Table.ColumnHeader>
                <Table.ColumnHeader w="56">Check</Table.ColumnHeader>
                <Table.ColumnHeader>Observed · action</Table.ColumnHeader>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {result.checks.map((check) => (
                <Table.Row key={check.id} data-testid={`preflight-${check.id}`} data-state={check.state}>
                  <Table.Cell verticalAlign="top">
                    <StatusText tone={TONE[check.state]}>{check.state}</StatusText>
                  </Table.Cell>
                  <Table.Cell verticalAlign="top" fontWeight="medium">
                    {check.title}
                  </Table.Cell>
                  <Table.Cell verticalAlign="top">
                    <Stack gap="1">
                      <Mono muted>{check.detail}</Mono>
                      {check.action && <Text fontSize="sm">{check.action}</Text>}
                    </Stack>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
          <Text fontSize="xs" color="fg.muted">
            Ran at {new Date(result.at).toLocaleTimeString()} in {formatDuration(result.durationMs)}. Not checkable from a dApp: the tenant&apos;s allowedDappOrigins (undisclosed by design — the failure lab provokes it) and the
            tenant&apos;s sponsorship configuration (a refusal shows only inside the wallet).
          </Text>
        </Stack>
      )}
    </SectionCard>
  );
}
