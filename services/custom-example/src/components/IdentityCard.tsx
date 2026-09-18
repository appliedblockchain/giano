import { Button, HStack, Table, Text } from '@chakra-ui/react';
import { useEffect, useMemo, useRef } from 'react';
import { shortHex } from '../lib/format';
import { useDemo } from '../state/store';
import { HexWithCopy, Mono, SectionCard, StatusText } from './primitives';

/**
 * R11: one passkey yields one address on every served chain. The dApp cannot compute the address
 * (no owner bytes through the public surface), so the observable proof is that every chain's provider
 * grants the same account. Agreement is shown; disagreement is a persistent violation (design.md D4).
 */
export function IdentityCard() {
  const { registry, state, referenceAccount, connect, recordViolation, isChainDisabled } = useDemo();
  const chains = useMemo(() => registry.list(), [registry, state.registryVersion]);
  const reported = useRef(new Set<number>());

  useEffect(() => {
    if (!referenceAccount) return;
    for (const [chainIdText, session] of Object.entries(state.sessions)) {
      const chainId = Number(chainIdText);
      if (!session.account || reported.current.has(chainId)) continue;
      if (session.account.toLowerCase() !== referenceAccount.toLowerCase()) {
        reported.current.add(chainId);
        recordViolation(
          'identity',
          'Address differs across chains',
          `${registry.get(chainId)?.config.name ?? chainId} (${chainId}) granted ${session.account}; the reference chain granted ${referenceAccount}. One passkey must yield one address on every served chain.`,
          chainId,
        );
      }
    }
  }, [state.sessions, referenceAccount, recordViolation, registry]);

  const connectedCount = Object.values(state.sessions).filter((session) => session.account).length;
  const identical = Object.values(state.sessions).filter((session) => session.account && referenceAccount && session.account.toLowerCase() === referenceAccount.toLowerCase()).length;

  return (
    <SectionCard
      id="identity"
      title="One address, every chain"
      description="One passkey, one address on every served chain. Each chain's provider grants an account; the demo compares them and a disagreement is a violation, not a detail."
      sdk={[
        ['eth_requestAccounts (per chain)', 'each chain\'s provider negotiates its own session and grants an account'],
        ['eth_accounts', 'the cached account per chain, answered without a popup'],
      ]}
    >
      <Table.Root size="sm" variant="line">
        <Table.Header>
          <Table.Row>
            <Table.ColumnHeader w="48">Chain</Table.ColumnHeader>
            <Table.ColumnHeader>Granted address</Table.ColumnHeader>
            <Table.ColumnHeader w="56">Status</Table.ColumnHeader>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {chains.map((chain) => {
            const session = state.sessions[chain.config.chainId];
            const account = session?.account;
            const isReference = !!account && !!referenceAccount && account.toLowerCase() === referenceAccount.toLowerCase() && Object.values(state.sessions).find((s) => s.account)?.account === account && connectedCount === 1;
            return (
              <Table.Row key={chain.config.chainId} data-testid={`identity-${chain.config.chainId}`}>
                <Table.Cell>
                  <HStack gap="2">
                    <Text fontSize="sm">{chain.config.name}</Text>
                    <Mono muted>{chain.config.chainId}</Mono>
                  </HStack>
                </Table.Cell>
                <Table.Cell>{account ? <HexWithCopy value={account} /> : <Mono muted>—</Mono>}</Table.Cell>
                <Table.Cell>
                  {!account ? (
                    <Button size="xs" variant="outline" onClick={() => void connect(chain.config.chainId)} disabled={isChainDisabled(chain.config.chainId)}>
                      Connect
                    </Button>
                  ) : isReference || !referenceAccount ? (
                    <Text fontSize="sm" color="fg.muted">
                      reference
                    </Text>
                  ) : account.toLowerCase() === referenceAccount.toLowerCase() ? (
                    <StatusText tone="green">identical</StatusText>
                  ) : (
                    <StatusText tone="red">differs</StatusText>
                  )}
                </Table.Cell>
              </Table.Row>
            );
          })}
        </Table.Body>
      </Table.Root>
      {connectedCount > 1 && identical === connectedCount && (
        <HStack gap="3" data-testid="identity-held">
          <StatusText tone="green">Invariant held</StatusText>
          <Text fontSize="sm" color="fg.muted">
            {connectedCount} of {connectedCount} connected chains grant {shortHex(referenceAccount)}. Re-checked on every connect.
          </Text>
        </HStack>
      )}
    </SectionCard>
  );
}
