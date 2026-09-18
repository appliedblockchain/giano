import { Alert, Box, Container, Skeleton, Stack, Tabs, Text } from '@chakra-ui/react';
import { Component, lazy, Suspense, type ErrorInfo, type ReactNode } from 'react';
import { loadRuntimeConfig } from './config';
import { ChainCard } from './components/ChainCard';
import { ConfigErrorScreen } from './components/ConfigErrorScreen';
import { Erc20Card } from './components/Erc20Card';
import { FailureLabCard } from './components/FailureLabCard';
import { HeaderBar } from './components/HeaderBar';
import { HomeTab } from './components/HomeTab';
import { IdentityCard } from './components/IdentityCard';
import { EventsCard, LedgerCard } from './components/LedgerCard';
import { ManagementCard } from './components/ManagementCard';
import { PreflightCard, PreflightLine } from './components/PreflightCard';
import { RawUserOpCard } from './components/RawUserOpCard';
import { SetupInfoCard } from './components/SetupInfoCard';
import { SigningCard } from './components/SigningCard';
import { TransactionsCard } from './components/TransactionsCard';
import { DemoProvider } from './state/store';
import { TABS, TabNavProvider, useTabNav, type TabId } from './state/tabs';

// wagmi + RainbowKit are a separate chunk: the thin-SDK page stays thin for everyone who never opens it.
const AdaptersCard = lazy(() => import('./components/AdaptersCard'));

// Read once, synchronously: index.html loads /config.js ahead of the bundle (src/config.ts).
const configResult = loadRuntimeConfig();

/** A failing card (or a failed lazy chunk) must never blank the page: the rest of the demo stays usable. */
class CardBoundary extends Component<{ name: string; children: ReactNode }, { error?: Error }> {
  state: { error?: Error } = {};
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[giano-demo] card "${this.props.name}" crashed`, error, info.componentStack);
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Alert.Root status="error" variant="subtle" id={this.props.name}>
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>The {this.props.name} card crashed</Alert.Title>
          <Alert.Description fontFamily="mono" fontSize="xs" wordBreak="break-all">
            {this.state.error.name}: {this.state.error.message}
          </Alert.Description>
        </Alert.Content>
      </Alert.Root>
    );
  }
}

/** One line under each tab's title: what the tab is for, in plain words. */
const TAB_INTRO: Record<TabId, string> = {
  home: '',
  setup: 'Is everything wired correctly, and which chain are you on? The checks here replace the timeouts a misconfiguration would otherwise produce.',
  wallet: 'Your smart account: the same address on every chain the wallet serves, and the management view for its passkeys and owners.',
  transactions: 'Send value or call a contract, and sign messages. Declare who you expect to pay for gas; the receipt says who did.',
  tokens: "Giano's test ERC-20, deployed at the same address on every chain: mint it, move it, approve a spender, sign a permit.",
  advanced: 'The pieces behind the simple buttons: the raw user-operation pipeline, and the wagmi and RainbowKit adapters.',
  'failure-lab': 'Every failure path, on purpose. Each control provokes one and records exactly what the SDK reported.',
  ledger: 'Everything this page did, in order, with its evidence. Export it to report an issue.',
};

function Page() {
  const { tab, go } = useTabNav();
  return (
    <>
      <HeaderBar />
      <PreflightLine />
      <Tabs.Root value={tab} onValueChange={(details) => go(details.value as TabId)} variant="line" size="md" lazyMount>
        <Box position="sticky" top="16" zIndex="docked" bg="bg.panel" borderBottomWidth="1px">
          <Tabs.List px={{ base: 4, md: 12 }} overflowX="auto" borderBottomWidth="0">
            {TABS.map((entry) => (
              <Tabs.Trigger key={entry.id} value={entry.id} data-testid={`tab-${entry.id}`}>
                {entry.label}
              </Tabs.Trigger>
            ))}
          </Tabs.List>
        </Box>
        <Container maxW="5xl" py={{ base: 6, md: 8 }}>
          {TABS.map((entry) => (
            <Tabs.Content key={entry.id} value={entry.id} p="0">
              <Stack gap="6">
                {TAB_INTRO[entry.id] && (
                  <Text color="fg.muted" fontSize="md">
                    {TAB_INTRO[entry.id]}
                  </Text>
                )}
                <TabBody id={entry.id} />
              </Stack>
            </Tabs.Content>
          ))}
        </Container>
      </Tabs.Root>
    </>
  );
}

function TabBody({ id }: { id: TabId }) {
  switch (id) {
    case 'home':
      return <HomeTab />;
    case 'setup':
      return (
        <>
          <PreflightCard />
          <ChainCard />
          <SetupInfoCard />
        </>
      );
    case 'wallet':
      return (
        <>
          <IdentityCard />
          <ManagementCard />
        </>
      );
    case 'transactions':
      return (
        <>
          <TransactionsCard />
          <SigningCard />
        </>
      );
    case 'tokens':
      return <Erc20Card />;
    case 'advanced':
      return (
        <>
          <RawUserOpCard />
          <CardBoundary name="adapters">
            <Suspense
              fallback={
                <Box id="adapters">
                  <Skeleton h="40" rounded="l3" />
                </Box>
              }
            >
              <AdaptersCard />
            </Suspense>
          </CardBoundary>
        </>
      );
    case 'failure-lab':
      return <FailureLabCard />;
    case 'ledger':
      return (
        <>
          <LedgerCard />
          <EventsCard />
        </>
      );
  }
}

export function App() {
  if (!configResult.ok) return <ConfigErrorScreen result={configResult} />;
  return (
    <DemoProvider config={configResult.config}>
      <TabNavProvider>
        <Page />
      </TabNavProvider>
    </DemoProvider>
  );
}
