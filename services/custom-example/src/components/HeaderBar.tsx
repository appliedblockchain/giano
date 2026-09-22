import { Alert, Badge, Box, Button, Heading, HStack, Text } from '@chakra-ui/react';
import { LuWallet } from 'react-icons/lu';
import { shortHex } from '../lib/format';
import { useDemo } from '../state/store';
import { Mono, StatusText } from './primitives';
import { ClipboardButton, ClipboardIconButton, ClipboardRoot } from './ui/clipboard';
import { ColorModeButton } from './ui/color-mode';

/** Brand, tenant label, wallet origin, connector version, session state, connect/disconnect. */
export function HeaderBar() {
  const { config, registry, state, selected, account, connect, disconnect, clearReconnectPrompt } = useDemo();
  const provider = registry.hasProvider(selected.chainId) ? registry.providerFor(selected.chainId) : undefined;
  const connected = provider?.isConnected() ?? false;
  const prompt = state.reconnectPrompt;

  return (
    <Box as="header" position="sticky" top="0" zIndex="sticky" bg="bg.panel" borderBottomWidth="1px">
      <HStack px={{ base: 4, md: 12 }} h="16" justify="space-between" gap="4">
        <HStack gap="3" minW="0">
          <Box w="8" h="8" rounded="l2" bg="brand.solid" color="brand.contrast" display="grid" placeItems="center" fontWeight="semibold">
            G
          </Box>
          <Heading size="md">Giano Demo</Heading>
          {config.appLabel && (
            <Badge colorPalette="brand" variant="subtle" data-testid="app-label">
              {config.appLabel}
            </Badge>
          )}
          <Mono muted>{registry.walletOrigin}</Mono>
        </HStack>
        <HStack gap="2" flexWrap="wrap" justify="flex-end">
          <StatusText tone={connected ? 'green' : 'gray'}>{connected ? 'connected' : 'not connected'}</StatusText>
          {account && (
            <HStack gap="1">
              <Badge colorPalette="gray" fontFamily="mono" size="md" data-testid="account">
                {shortHex(account)}
              </Badge>
              <ClipboardRoot value={account}>
                <ClipboardIconButton aria-label="Copy address" variant="ghost" />
              </ClipboardRoot>
            </HStack>
          )}
          {account ? (
            <Button size="sm" variant="ghost" colorPalette="gray" onClick={() => void disconnect()}>
              <LuWallet /> Disconnect
            </Button>
          ) : (
            <Button size="sm" colorPalette="brand" onClick={() => void connect()} data-testid="connect">
              <LuWallet /> Connect on {selected.config.name}
            </Button>
          )}
          <ColorModeButton />
        </HStack>
      </HStack>
      {prompt && (
        <Box px={{ base: 4, md: 12 }} pb="3">
          <Alert.Root status="warning" variant="subtle">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>Your wallet session ended</Alert.Title>
              <Alert.Description>
                The wallet no longer recognises the session on {registry.get(prompt.chainId)?.config.name ?? prompt.chainId} ({String(prompt.error.code)}: {prompt.error.message}). The connector dropped its
                cache. Reconnect to continue; the ledger and events are kept.
              </Alert.Description>
              <HStack pt="2">
                <Button
                  size="sm"
                  colorPalette="brand"
                  onClick={() => {
                    clearReconnectPrompt();
                    void connect(prompt.chainId);
                  }}
                >
                  <LuWallet /> Reconnect
                </Button>
                <Button size="sm" variant="ghost" colorPalette="gray" onClick={clearReconnectPrompt}>
                  Dismiss
                </Button>
              </HStack>
            </Alert.Content>
          </Alert.Root>
        </Box>
      )}
      {state.violations.length > 0 && (
        <Box px={{ base: 4, md: 12 }} pb="3">
          {state.violations.map((violation) => (
            <ViolationBanner key={violation.id} id={violation.id} title={violation.title} detail={violation.detail} />
          ))}
        </Box>
      )}
    </Box>
  );
}

function ViolationBanner({ id, title, detail }: { id: string; title: string; detail: string }) {
  const { dismissViolation } = useDemo();
  return (
    <Alert.Root status="error" variant="subtle" mb="2" data-testid="violation">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>Violation: {title}</Alert.Title>
        <Alert.Description>
          <Text as="span" fontFamily="mono" fontSize="xs" wordBreak="break-all">
            {detail}
          </Text>
        </Alert.Description>
        <HStack pt="2">
          <ClipboardRoot value={`${title}\n${detail}`}>
            <ClipboardButton size="xs" colorPalette="red" variant="solid" />
          </ClipboardRoot>
          <Button size="xs" variant="outline" colorPalette="red" onClick={() => dismissViolation(id)}>
            Dismiss
          </Button>
        </HStack>
      </Alert.Content>
    </Alert.Root>
  );
}
