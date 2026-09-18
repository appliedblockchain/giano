import { Alert, Badge, Box, Button, Container, HStack, Heading, NativeSelect, Spinner, Stack, Tabs, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useState } from 'react';
import { LuLayoutDashboard, LuRefreshCw, LuSettings, LuShieldCheck, LuUsers, LuWallet, LuHistory } from 'react-icons/lu';
import { Copyable, notifyError } from './components/ui';
import { deploymentKey, getAdminConfig, initialDeployment, rememberDeployment, type Deployment } from './config';
import { usePaymaster } from './hooks/usePaymaster';
import { connectWallet, getAuthorisedAccount, getInjectedProvider, type ConnectedWallet } from './lib/chain';
import { HealthPanel } from './panels/HealthPanel';
import { HistoryPanel } from './panels/HistoryPanel';
import { OverviewPanel } from './panels/OverviewPanel';
import { RolesPanel } from './panels/RolesPanel';
import { SettingsPanel } from './panels/SettingsPanel';
import { TenantsPanel } from './panels/TenantsPanel';

export function App() {
  const { deployments } = getAdminConfig();
  const [deployment, setDeployment] = useState(() => initialDeployment(deployments));
  const [wallet, setWallet] = useState<ConnectedWallet>();
  const [connecting, setConnecting] = useState(false);
  const { client, overview, health, myRoles, rosterOnChain, loading, error, lastUpdated, refresh } = usePaymaster(deployment, wallet);

  /**
   * Switching environments drops the connected wallet.
   *
   * The wallet is bound to the old chain, and its roles were read from the old paymaster — keeping
   * it would leave the console offering actions an account may not hold on the deployment now on
   * screen. Reconnecting is one click and makes the chain check run again.
   */
  const selectDeployment = useCallback(
    (next: Deployment) => {
      if (deploymentKey(next) === deploymentKey(deployment)) return;
      setWallet(undefined);
      setDeployment(next);
      rememberDeployment(next);
    },
    [deployment],
  );

  // Restore a wallet the user already authorised, so a reload does not demand a fresh prompt.
  useEffect(() => {
    void getAuthorisedAccount(deployment)
      .then((restored) => restored && setWallet(restored))
      .catch(() => undefined);
  }, [deployment]);

  // A wallet that switches account or network mid-session would otherwise leave the console
  // signing as somebody it is no longer connected to.
  useEffect(() => {
    const provider = getInjectedProvider();
    if (!provider) return;
    const reload = () => window.location.reload();
    provider.on?.('accountsChanged', reload);
    provider.on?.('chainChanged', reload);
    return () => {
      provider.removeListener?.('accountsChanged', reload);
      provider.removeListener?.('chainChanged', reload);
    };
  }, []);

  const connect = useCallback(async () => {
    setConnecting(true);
    try {
      setWallet(await connectWallet(deployment));
    } catch (cause) {
      notifyError('Could not connect a wallet', cause);
    } finally {
      setConnecting(false);
    }
  }, [deployment]);

  return (
    <Box minH="100vh">
      <Box borderBottomWidth="1px" bg="surface" position="sticky" top="0" zIndex="docked">
        <Container maxW="7xl" py="3">
          <HStack justify="space-between" gap="4" flexWrap="wrap">
            <HStack gap="3">
              <Heading size="md">Giano paymaster</Heading>
              {deployments.length > 1 ? (
                <NativeSelect.Root size="sm" width="auto">
                  <NativeSelect.Field
                    value={deploymentKey(deployment)}
                    onChange={(event) => {
                      const next = deployments.find((candidate) => deploymentKey(candidate) === event.currentTarget.value);
                      if (next) selectDeployment(next);
                    }}
                    aria-label="Deployment"
                  >
                    {deployments.map((candidate) => (
                      <option key={deploymentKey(candidate)} value={deploymentKey(candidate)}>
                        {candidate.label} — chain {candidate.chainId}
                      </option>
                    ))}
                  </NativeSelect.Field>
                  <NativeSelect.Indicator />
                </NativeSelect.Root>
              ) : (
                <Badge colorPalette="brand" variant="subtle">
                  {deployment.label}
                </Badge>
              )}
              <Badge variant="outline">chain {deployment.chainId}</Badge>
              {overview && <Copyable value={overview.address} label="Paymaster address" />}
            </HStack>

            <HStack gap="3">
              {lastUpdated && (
                <Text fontSize="xs" color="fg.muted">
                  updated {lastUpdated.toLocaleTimeString()}
                </Text>
              )}
              <Button size="sm" variant="ghost" onClick={() => void refresh()} loading={loading} aria-label="Refresh">
                <LuRefreshCw />
              </Button>
              {wallet ? (
                <HStack gap="2">
                  <Badge colorPalette="green" variant="subtle">
                    {myRoles.length > 0 ? `${myRoles.length} role${myRoles.length === 1 ? '' : 's'}` : 'no roles'}
                  </Badge>
                  <Copyable value={wallet.address} label="Connected account" />
                </HStack>
              ) : (
                <Button size="sm" colorPalette="brand" onClick={() => void connect()} loading={connecting} loadingText="Connecting">
                  <LuWallet /> Connect wallet
                </Button>
              )}
            </HStack>
          </HStack>
        </Container>
      </Box>

      <Container maxW="7xl" py="6">
        {!wallet && (
          <Alert.Root status="info" mb="4">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>Read-only</Alert.Title>
              <Alert.Description>
                Everything here is read straight from the chain, so no wallet is needed to inspect a deployment. Connect one to act — the console never
                sees a key, it only asks your wallet to sign.
              </Alert.Description>
            </Alert.Content>
          </Alert.Root>
        )}

        {error && (
          <Alert.Root status="error" mb="4">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>Could not read the paymaster</Alert.Title>
              <Alert.Description>{error}</Alert.Description>
            </Alert.Content>
          </Alert.Root>
        )}

        {!overview && loading && (
          <Stack align="center" py="16" gap="3">
            <Spinner size="lg" color="brand.solid" />
            <Text color="fg.muted">Reading the paymaster…</Text>
          </Stack>
        )}

        {overview && client && (
          <Tabs.Root defaultValue="overview" lazyMount unmountOnExit={false}>
            <Tabs.List mb="4">
              <Tabs.Trigger value="overview">
                <LuLayoutDashboard /> Overview
              </Tabs.Trigger>
              <Tabs.Trigger value="tenants">
                <LuUsers /> Tenants ({overview.tenants.length})
              </Tabs.Trigger>
              <Tabs.Trigger value="roles">
                <LuShieldCheck /> Roles
              </Tabs.Trigger>
              <Tabs.Trigger value="settings">
                <LuSettings /> Settings
              </Tabs.Trigger>
              <Tabs.Trigger value="history">
                <LuHistory /> History
              </Tabs.Trigger>
              <Tabs.Trigger value="health">
                <LuShieldCheck /> Health
                {health && health.level !== 'ok' && (
                  <Badge colorPalette={health.level === 'fail' ? 'red' : 'orange'} variant="solid" ml="1" size="sm">
                    !
                  </Badge>
                )}
              </Tabs.Trigger>
            </Tabs.List>

            <Tabs.Content value="overview">
              <OverviewPanel overview={overview} />
            </Tabs.Content>
            <Tabs.Content value="tenants">
              <TenantsPanel
                client={client}
                tenants={overview.tenants}
                myRoles={myRoles}
                connected={wallet !== undefined}
                rosterOnChain={rosterOnChain}
                refresh={refresh}
              />
            </Tabs.Content>
            <Tabs.Content value="roles">
              <RolesPanel client={client} roles={overview.roles} myRoles={myRoles} account={wallet?.address} refresh={refresh} />
            </Tabs.Content>
            <Tabs.Content value="settings">
              <SettingsPanel client={client} overview={overview} myRoles={myRoles} refresh={refresh} />
            </Tabs.Content>
            <Tabs.Content value="history">
              <HistoryPanel client={client} />
            </Tabs.Content>
            <Tabs.Content value="health">{health && <HealthPanel health={health} />}</Tabs.Content>
          </Tabs.Root>
        )}
      </Container>
    </Box>
  );
}
