import '@rainbow-me/rainbowkit/styles.css';
import { createGianoConnector, giano } from '@appliedblockchain/giano-connector';
import { Button, HStack, Text } from '@chakra-ui/react';
import { ConnectButton, connectorsForWallets, RainbowKitProvider } from '@rainbow-me/rainbowkit';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { LuLayers, LuSend, LuWallet } from 'react-icons/lu';
import { createConfig, custom, useAccount, useConnect, useDisconnect, useSwitchChain, WagmiProvider, type Config } from 'wagmi';
import type { Address } from '../lib/format';
import { useDemo, useSectionEntries } from '../state/store';
import { Mono, Outcomes, SectionCard, StatusText } from './primitives';

/**
 * The two adapters the SDK publishes over the same provider: `createGianoConnector` (wagmi) and
 * `giano()` (RainbowKit). switchChain is expected to throw; a silent success would be the finding.
 * Lazy-loaded (App.tsx) so the thin-SDK bundle stays thin for everyone who never opens it.
 */
export default function AdaptersCard() {
  const { registry, state, selected } = useDemo();
  const chains = useMemo(() => registry.list(), [registry, state.registryVersion]);

  // One wagmi config per selected chain: the connector is bound to that chain's provider (MC-01).
  const { config, queryClient } = useMemo(() => {
    const entry = registry.require(selected.chainId);
    const provider = registry.providerFor(selected.chainId);
    const others = chains.filter((chain) => chain.config.chainId !== selected.chainId).map((chain) => chain.chain);
    const connectors = connectorsForWallets([{ groupName: 'Giano', wallets: [giano({ provider })] }], { appName: 'Giano Demo', projectId: 'giano-demo' });
    const config = createConfig({
      chains: [entry.chain, ...others] as [typeof entry.chain, ...(typeof entry.chain)[]],
      transports: Object.fromEntries([entry, ...chains.filter((chain) => chain.config.chainId !== selected.chainId)].map((chain) => [chain.config.chainId, custom(chain.config.chainId === selected.chainId ? provider : { request: chain.publicClient.request })])),
      connectors: [createGianoConnector({ provider }), ...connectors],
      multiInjectedProviderDiscovery: false,
    });
    return { config, queryClient: new QueryClient() };
  }, [registry, chains, selected.chainId]);

  // reconnectOnMount is OFF on purpose (finding G7): wagmi's mount-time reconnect calls the Giano
  // connector's isAuthorized() — true as soon as the raw provider has a cached session — and then
  // connect(), which always issues eth_requestAccounts. That opens a second, orphaned Connect popup
  // and every later request fails with "another request is already pending". Connecting through
  // wagmi is an explicit click in this card.
  return (
    <WagmiProvider config={config} key={selected.chainId} reconnectOnMount={false}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider>
          <AdaptersInner config={config} />
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

function AdaptersInner({ config }: { config: Config }) {
  const demo = useDemo();
  const { selected, account: rawAccount, run, recordViolation, isChainDisabled } = demo;
  const entries = useSectionEntries('adapters');
  const { address, status, chainId, connector } = useAccount();
  const { connectAsync, connectors } = useConnect();
  const { disconnectAsync } = useDisconnect();
  const { switchChainAsync } = useSwitchChain();
  const [busy, setBusy] = useState<string | null>(null);
  const other = config.chains.find((chain) => chain.id !== selected.chainId);
  const gianoConnector = connectors.find((candidate) => candidate.id === 'giano') ?? connectors[0];

  const connectWagmi = async () => {
    setBusy('connect');
    await run({ section: 'adapters', label: 'Connect via wagmi (createGianoConnector)', method: 'connector.connect', account: rawAccount, noBalances: true }, async () => {
      const result = await connectAsync({ connector: gianoConnector });
      const granted = result.accounts[0] as Address;
      if (rawAccount && granted.toLowerCase() !== rawAccount.toLowerCase()) recordViolation('adapters', 'wagmi granted a different account than the raw provider', `${granted} vs ${rawAccount}`);
      return { accounts: result.accounts, chainId: result.chainId };
    });
    setBusy(null);
  };

  const trySwitch = async () => {
    if (!other) return;
    setBusy('switch');
    await run({ section: 'adapters', label: `wagmi switchChain → ${other.name}`, method: 'connector.switchChain', params: { chainId: other.id }, account: rawAccount, expected: true, noBalances: true }, async () => {
      const result = await switchChainAsync({ chainId: other.id });
      recordViolation('adapters', 'wagmi switchChain succeeded', `Giano binds one chain per connector; expected UnsupportedChainSwitchError, got ${JSON.stringify(result)}`);
      return result;
    });
    setBusy(null);
  };

  const sendViaWagmi = async () => {
    if (!address) return;
    setBusy('send');
    await run({ section: 'adapters', label: 'wagmi sendTransaction + waitForUserOperationReceipt', method: 'connector.sendTransaction', params: [{ to: address, value: '0x0' }], account: address, declaredPayer: 'sponsored', sponsoredSend: true }, async (api) => {
      const { sendTransaction } = await import('wagmi/actions');
      const hash = await sendTransaction(config, { to: address, value: 0n });
      api.update({ userOpHash: hash, status: 'submitted' });
      const gianoLike = connector as unknown as { waitForUserOperationReceipt?: (hash: `0x${string}`) => Promise<unknown> };
      const receipt = gianoLike.waitForUserOperationReceipt
        ? ((await gianoLike.waitForUserOperationReceipt(hash)) as never)
        : await api.provider.request({ method: 'waitForUserOperationReceipt', params: [hash] });
      api.update({ receipt: receipt as never, txHash: (receipt as { receipt?: { transactionHash?: string } })?.receipt?.transactionHash });
      return receipt;
    });
    setBusy(null);
  };

  const disabled = isChainDisabled(selected.chainId);

  return (
    <SectionCard id="adapters" title="Adapters · wagmi and RainbowKit" description="The two adapters the SDK publishes over the same provider. switchChain is expected to throw; a silent success would be the finding.">
      <HStack gap="4" flexWrap="wrap">
        <StatusText tone={status === 'connected' ? 'green' : 'gray'}>wagmi {status}</StatusText>
        <Mono muted>
          connector {connector?.id ?? '—'} · chainId {chainId ?? '—'} · {address ?? 'no account'}
        </Mono>
      </HStack>
      <HStack gap="3" flexWrap="wrap">
        {status === 'connected' ? (
          <Button size="sm" variant="outline" onClick={() => void disconnectAsync()}>
            Disconnect wagmi
          </Button>
        ) : (
          <Button size="sm" colorPalette="brand" onClick={() => void connectWagmi()} disabled={disabled} loading={busy === 'connect'}>
            <LuWallet /> Connect via wagmi
          </Button>
        )}
        <Button size="sm" variant="outline" colorPalette="orange" onClick={() => void trySwitch()} disabled={status !== 'connected' || !other} loading={busy === 'switch'}>
          <LuLayers /> switchChain → {other?.name ?? 'n/a'}
        </Button>
        <Button size="sm" variant="outline" onClick={() => void sendViaWagmi()} disabled={status !== 'connected' || disabled} loading={busy === 'send'} loadingText="Awaiting receipt…">
          <LuSend /> Send + waitForUserOperationReceipt
        </Button>
      </HStack>
      <HStack gap="4" flexWrap="wrap" align="center">
        <Text fontSize="sm" fontWeight="medium">
          RainbowKit · giano({'{'} provider {'}'})
        </Text>
        <ConnectButton label="Open RainbowKit connect modal" showBalance={false} chainStatus="name" />
        <Text fontSize="sm" color="fg.muted">
          Giano is listed as a wallet; connecting through it must grant the same account as the raw provider.
        </Text>
      </HStack>
      <Outcomes entries={entries} />
    </SectionCard>
  );
}
