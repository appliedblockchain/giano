import { Box, Button, Card, Heading, HStack, SimpleGrid, Stack, Text } from '@chakra-ui/react';
import { LuArrowRight, LuCoins, LuFlaskConical, LuKeyRound, LuScrollText, LuSend, LuWallet } from 'react-icons/lu';
import { summarise } from '../lib/preflight';
import { useDemo } from '../state/store';
import { useTabNav, type TabId } from '../state/tabs';
import { StatusText } from './primitives';

/**
 * The landing tab: what this app is, what you can do here, and how to start. Written for a person
 * evaluating Giano, with the technical depth one tab away.
 */
export function HomeTab() {
  const { state, account, selected, connect, config } = useDemo();
  const { go } = useTabNav();
  const preflight = state.preflight ? summarise(state.preflight) : undefined;

  const features: Array<{ tab: TabId; icon: React.ReactNode; title: string; text: string; sdk: string }> = [
    { tab: 'setup', icon: <LuWallet />, title: 'Connect with a passkey', text: 'No seed phrase, no extension. Your passkey lives on the wallet origin; this app only ever receives your address.', sdk: 'eth_requestAccounts' },
    { tab: 'transactions', icon: <LuSend />, title: 'Transact without holding gas', text: 'Send value or call a contract while the application pays the fee. The receipt tells you who actually paid.', sdk: 'eth_sendTransaction' },
    { tab: 'wallet', icon: <LuKeyRound />, title: 'One address on every chain', text: 'The same passkey yields the same smart-account address on each chain the wallet serves. This app checks it, every time.', sdk: 'one provider per chain' },
    { tab: 'tokens', icon: <LuCoins />, title: 'Use tokens', text: "Mint Giano's test token, transfer it, approve a spender, sign a permit — with balances recorded before and after.", sdk: 'eth_signTypedData_v4' },
    { tab: 'wallet', icon: <LuKeyRound />, title: 'Manage your wallet', text: 'Add a passkey, a second device or an externally-owned account, or remove one — on the wallet origin, not here.', sdk: 'openWalletManagement()' },
    { tab: 'failure-lab', icon: <LuFlaskConical />, title: 'See how it fails', text: 'Every failure path has a button: a blocked popup, a chain the wallet does not serve, a rejected request. Each shows exactly what the SDK reports.', sdk: 'typed errors' },
  ];

  return (
    <Stack gap="8">
      <Stack gap="4" pt="4">
        <Heading size="2xl" lineHeight="shorter">
          A wallet you open with a passkey. An app that shows you everything it does.
        </Heading>
        <Text fontSize="lg" color="fg.muted" maxW="3xl">
          This is the reference application for <b>Giano</b>, a smart-account wallet secured by passkeys. It is built exactly the way any client application would be built — on the published SDK
          and nothing else — and its job is to demonstrate every feature, expose every failure, and record every outcome so nothing is left to guesswork.
        </Text>
        <HStack gap="3" flexWrap="wrap">
          {account ? (
            <Button colorPalette="brand" onClick={() => go('transactions')}>
              Make a transaction <LuArrowRight />
            </Button>
          ) : (
            <Button colorPalette="brand" onClick={() => void connect(selected.chainId)} data-testid="home-connect">
              <LuWallet /> Connect on {selected.config.name}
            </Button>
          )}
          <Button variant="outline" onClick={() => go('setup')}>
            Check the setup
          </Button>
          <Button variant="ghost" colorPalette="gray" onClick={() => go('ledger')}>
            <LuScrollText /> Open the ledger
          </Button>
        </HStack>
        <HStack gap="4" flexWrap="wrap">
          {preflight && <StatusText tone={preflight.state === 'pass' ? 'green' : preflight.state === 'warn' ? 'orange' : 'red'}>{preflight.state === 'pass' ? 'setup verified' : `${preflight.fails.length + preflight.warns.length} setup issue(s)`}</StatusText>}
          <StatusText tone={account ? 'green' : 'gray'}>{account ? `connected on ${selected.config.name}` : 'not connected'}</StatusText>
          <Text fontSize="sm" color="fg.muted">
            wallet {new URL(config.walletUrl).host} · {config.chains.length} chain{config.chains.length > 1 ? 's' : ''}
            {config.appLabel ? ` · ${config.appLabel}` : ''}
          </Text>
        </HStack>
      </Stack>

      <Stack gap="3">
        <Heading size="md">What you can do here</Heading>
        <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} gap="4">
          {features.map((feature) => (
            <Card.Root key={feature.title} variant="outline" cursor="pointer" onClick={() => go(feature.tab)} _hover={{ borderColor: 'brand.solid' }}>
              <Card.Body>
                <Stack gap="2">
                  <Box color="brand.fg">{feature.icon}</Box>
                  <Text fontWeight="semibold">{feature.title}</Text>
                  <Text fontSize="sm" color="fg.muted">
                    {feature.text}
                  </Text>
                  <Text fontSize="xs" fontFamily="mono" color="fg.subtle">
                    {feature.sdk}
                  </Text>
                </Stack>
              </Card.Body>
            </Card.Root>
          ))}
        </SimpleGrid>
      </Stack>

      <Stack gap="3">
        <Heading size="md">How it works</Heading>
        <SimpleGrid columns={{ base: 1, md: 3 }} gap="4">
          {[
            ['1 · Connect', 'Pick a chain and connect. A popup on the wallet origin asks for your passkey; the app receives your smart-account address and nothing more.'],
            ['2 · Act', 'Send, sign, mint, manage. Each action is a Giano SDK call; the tab names the calls it uses, and the wallet asks for consent in its own window.'],
            ['3 · Read the record', 'Every outcome is written to the ledger with its hashes, receipt, balances and errors. Export it as JSON to report an issue.'],
          ].map(([title, text]) => (
            <Stack key={title} gap="1" p="4" borderWidth="1px" rounded="l3">
              <Text fontWeight="semibold">{title}</Text>
              <Text fontSize="sm" color="fg.muted">
                {text}
              </Text>
            </Stack>
          ))}
        </SimpleGrid>
      </Stack>

      <Stack gap="2" p="4" bg="bg.subtle" rounded="l3">
        <Text fontWeight="semibold">Why this app exists</Text>
        <Text fontSize="sm" color="fg.muted">
          To challenge Giano, not to flatter it. It reaches every method the SDK exposes, provokes every failure path on purpose, and keeps a persistent record of what happened. For developers, each
          card names the SDK calls it uses and folds the raw payloads behind <i>Technical details</i>. The full write-up is in <code>specs/DEMO-REQUIREMENTS.md</code> and{' '}
          <code>specs/DEMO-SPECS.md</code>.
        </Text>
      </Stack>
    </Stack>
  );
}
