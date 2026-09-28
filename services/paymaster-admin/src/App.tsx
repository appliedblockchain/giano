import { Alert, Badge, Box, Button, Container, HStack, Heading, NativeSelect, Popover, Portal, Spinner, Stack, Tabs, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { LuLayoutDashboard, LuRefreshCw, LuSettings, LuShieldCheck, LuUsers, LuWallet, LuHistory } from 'react-icons/lu';
import { Copyable, notifyError } from './components/ui';
import { deploymentKey, getAdminConfig, initialDeployment, rememberDeployment, type Deployment } from './config';
import { usePaymaster } from './hooks/usePaymaster';
import { ChainNotAddedError, connectOnChain, getAuthorisedAccount, getInjectedProvider, isUserRejection, networkDetails, type ConnectedWallet } from './lib/chain';
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
  const [notAdded, setNotAdded] = useState<ChainNotAddedError>();
  /**
   * Set while the console is driving the wallet.
   *
   * Connecting can now include a network switch, which the wallet announces as `chainChanged` —
   * and the listener below answers that by reloading, which would abandon the prompt the operator
   * has just approved. Changes made in the wallet itself still reload, which is what it is for.
   */
  const connectingRef = useRef(false);
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
      setNotAdded(undefined);
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
    // A switch the console itself asked for is finished by the connect flow, which rebinds the
    // client; reloading in the middle of that would throw away the prompt the operator just approved.
    const reload = () => {
      if (connectingRef.current) return;
      window.location.reload();
    };
    provider.on?.('accountsChanged', reload);
    provider.on?.('chainChanged', reload);
    return () => {
      provider.removeListener?.('accountsChanged', reload);
      provider.removeListener?.('chainChanged', reload);
    };
  }, []);

  const connect = useCallback(async () => {
    setConnecting(true);
    setNotAdded(undefined);
    connectingRef.current = true;
    try {
      setWallet(await connectOnChain(deployment));
    } catch (cause) {
      if (cause instanceof ChainNotAddedError) setNotAdded(cause);
      else if (!isUserRejection(cause)) notifyError('Could not connect a wallet', cause);
    } finally {
      connectingRef.current = false;
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
                        {candidate.name} — chain {candidate.chainId}
                      </option>
                    ))}
                  </NativeSelect.Field>
                  <NativeSelect.Indicator />
                </NativeSelect.Root>
              ) : (
                <Badge colorPalette="brand" variant="subtle">
                  {deployment.name}
                </Badge>
              )}
              {deployments.length === 1 && <Badge variant="outline">chain {deployment.chainId}</Badge>}
              {overview && <Field label="Paymaster" value={overview.address} />}
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
                <WalletCard wallet={wallet} deployment={deployment} roles={myRoles.length} />
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
        {!wallet && notAdded && (
          <Alert.Root status="warning" mb="4">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>Add {notAdded.deployment.name} in your wallet</Alert.Title>
              <Alert.Description>
                Your wallet would not take this network from the console. It said: {notAdded.walletMessage}
              </Alert.Description>
              <Stack gap="1" mt="3">
                {networkDetails(notAdded.deployment, notAdded.rpcUrl).map(({ label, value }) => (
                  <HStack key={label} gap="3">
                    <Text fontSize="xs" color="fg.muted" minW="28" textAlign="right">
                      {label}
                    </Text>
                    <Copyable value={value} label={label} />
                  </HStack>
                ))}
              </Stack>
              <Text fontSize="xs" color="fg.muted" mt="2">
                Wallets generally accept only an HTTPS address, localhost or 127.0.0.1 as an RPC URL. If yours will not take the address above, any
                address of your own that reaches the same node does just as well.
              </Text>
              <Box mt="3">
                <Button size="sm" colorPalette="brand" onClick={() => void connect()} loading={connecting} loadingText="Connecting">
                  Connect again
                </Button>
              </Box>
            </Alert.Content>
          </Alert.Root>
        )}

        {!wallet && !notAdded && (
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

/**
 * A value with the word for what it is.
 *
 * Two bare hex strings sat in this header — the paymaster and the connected account — and nothing
 * said which was which. They are the same shape, they are both copyable, and getting them the wrong
 * way round is exactly the mistake an operator cannot afford to make.
 */
function Field({ label, value }: { label: string; value: string }) {
  return (
    <HStack gap="2">
      <Text fontSize="2xs" color="fg.muted" textTransform="uppercase" letterSpacing="wide" fontWeight="medium">
        {label}
      </Text>
      <Copyable value={value} label={label} />
    </HStack>
  );
}

/**
 * What the console is signing as.
 *
 * Occupies the same slot and about the same width as the connect button it replaces. An account
 * address is 42 characters and is never abbreviated here — see {@link Copyable} — so shown inline
 * it wraps the header onto a second row the moment a wallet connects, and every control in it
 * moves. It goes in a panel instead: the button carries the state worth seeing at a glance, and
 * the values an operator actually reads are one click away and full width.
 *
 * The network is named there even though a connected wallet is always on the deployment's chain —
 * that it agrees is the thing worth showing, and it is the half an operator with several
 * environments open will otherwise assume.
 */
function WalletCard({ wallet, deployment, roles }: { wallet: ConnectedWallet; deployment: Deployment; roles: number }) {
  return (
    <Popover.Root positioning={{ placement: 'bottom-end' }}>
      <Popover.Trigger asChild>
        <Button size="sm" variant="outline">
          <Box boxSize="2" rounded="full" bg="green.solid" aria-hidden="true" />
          Connected
          <Badge colorPalette={roles > 0 ? 'green' : 'gray'} variant="subtle">
            {roles > 0 ? `${roles} role${roles === 1 ? '' : 's'}` : 'no roles'}
          </Badge>
        </Button>
      </Popover.Trigger>
      <Portal>
        <Popover.Positioner>
          <Popover.Content width="auto" maxW="md">
            <Popover.Arrow />
            <Popover.Body>
              <Stack gap="3">
                <Field label="Account" value={wallet.address} />
                <HStack gap="2">
                  <Text fontSize="2xs" color="fg.muted" textTransform="uppercase" letterSpacing="wide" fontWeight="medium">
                    Network
                  </Text>
                  <Text fontSize="sm">
                    {deployment.name} · chain {deployment.chainId}
                  </Text>
                </HStack>
                <HStack gap="2">
                  <Text fontSize="2xs" color="fg.muted" textTransform="uppercase" letterSpacing="wide" fontWeight="medium">
                    Roles
                  </Text>
                  <Text fontSize="sm">
                    {roles > 0 ? `${roles} on this paymaster` : 'none on this paymaster — reads only'}
                  </Text>
                </HStack>
              </Stack>
            </Popover.Body>
          </Popover.Content>
        </Popover.Positioner>
      </Portal>
    </Popover.Root>
  );
}
