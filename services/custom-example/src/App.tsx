import { Badge, Box, Button, Container, Heading, HStack, Stack, Text } from '@chakra-ui/react';
import { LuLogOut, LuWallet } from 'react-icons/lu';
import { ClipboardIconButton, ClipboardRoot } from './components/ui/clipboard';
import { Erc20Panel } from './components/Erc20Panel';
import { SectionCard } from './components/SectionCard';
import { SponsorshipPanel } from './components/SponsorshipPanel';
import { WalletPanel } from './components/WalletPanel';
import { config } from './config';
import { useWallet } from './hooks/useWallet';
import { shortAddress } from './lib/errors';

export function App() {
  const { account, connecting, connect, disconnect } = useWallet();

  return (
    <Container maxW="3xl" py={{ base: 6, md: 10 }}>
      <Stack gap="6">
        <SectionCard
          title={
            <HStack gap="2">
              <Text>Giano Demo</Text>
              {config.appLabel && (
                <Badge colorPalette="brand" variant="subtle" data-testid="app-label">
                  {config.appLabel}
                </Badge>
              )}
            </HStack>
          }
          description="Passkey smart-account wallet · thin two-origin SDK"
        >
          <Stack direction={{ base: 'column', md: 'row' }} justify="space-between" align={{ md: 'center' }} gap="4">
            <Text fontSize="sm" color="fg.muted" maxW="md">
              Signing and passkeys live on the wallet origin popup — this dApp ships no WebAuthn or bundler code.
            </Text>
            {account ? (
              <HStack gap="2" flexWrap="wrap">
                <Badge colorPalette="accent" size="lg" fontFamily="mono">
                  {shortAddress(account)}
                </Badge>
                <ClipboardRoot value={account}>
                  <ClipboardIconButton aria-label="Copy address" />
                </ClipboardRoot>
                <Button variant="outline" colorPalette="brand" onClick={disconnect}>
                  <LuLogOut /> Disconnect
                </Button>
              </HStack>
            ) : (
              <Button colorPalette="brand" onClick={connect} loading={connecting} loadingText="Connecting…">
                <LuWallet /> Connect wallet
              </Button>
            )}
          </Stack>
        </SectionCard>

        {account ? (
          <>
            <WalletPanel account={account} />
            <Erc20Panel account={account} defaultToken={config.defaultTokenAddress} />
            <SponsorshipPanel />
          </>
        ) : (
          <Box color="whiteAlpha.900" textAlign="center" py="6">
            <Heading size="md" mb="2">
              Connect to get started
            </Heading>
            <Text fontSize="sm" maxW="md" mx="auto">
              The wallet stack must be running (<code>deploy/docker-compose.e2e.yml</code>). Connecting opens the wallet origin
              popup to create or unlock your passkey smart account.
            </Text>
          </Box>
        )}
      </Stack>
    </Container>
  );
}
