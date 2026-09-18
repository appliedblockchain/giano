import { Alert, Box, Code, Container, List, Stack, Text } from '@chakra-ui/react';
import type { ConfigResult } from '../config';

/**
 * Rendered instead of the app when the runtime configuration is invalid (demo-deployment spec):
 * nothing else is available, and no provider is constructed. Names the fields.
 */
export function ConfigErrorScreen({ result }: { result: Extract<ConfigResult, { ok: false }> }) {
  return (
    <Container maxW="3xl" py="16">
      <Alert.Root status="error" variant="subtle" alignItems="flex-start">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>This deployment is misconfigured</Alert.Title>
          <Alert.Description>
            <Stack gap="3">
              <Text>
                {result.source === 'container'
                  ? 'The container rendered a runtime configuration this build cannot use. Fix the GIANO_* environment and restart; nothing else is available until then.'
                  : result.source === 'dev-env'
                    ? 'The GIANO_* variables in .env.development / .env.local are incomplete or invalid.'
                    : 'No runtime configuration was found: no /config.js was rendered and no GIANO_* variables are set for development.'}
              </Text>
              <Box>
                <List.Root gap="1">
                  {result.issues.map((issue, index) => (
                    <List.Item key={`${issue.path}-${index}`}>
                      <Code fontSize="sm">{issue.path}</Code> {issue.message}
                    </List.Item>
                  ))}
                </List.Root>
              </Box>
              <Text fontSize="sm" color="fg.muted">
                Contract: <Code fontSize="xs">GIANO_WALLET_URL</Code> (required), <Code fontSize="xs">GIANO_CHAINS</Code> (required JSON array of chainId, name, rpcUrl, optional explorerUrl and defaultToken),{' '}
                <Code fontSize="xs">GIANO_OTHER_WALLET_URL</Code> and <Code fontSize="xs">GIANO_APP_LABEL</Code> (optional). The scalar pair <Code fontSize="xs">GIANO_CHAIN_ID</Code> /{' '}
                <Code fontSize="xs">GIANO_CHAIN_B_ID</Code> is still accepted by the container for one release.
              </Text>
            </Stack>
          </Alert.Description>
        </Alert.Content>
      </Alert.Root>
    </Container>
  );
}
