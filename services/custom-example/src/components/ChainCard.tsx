import { Button, HStack, Input, SegmentGroup, Stack, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { LuLayers, LuRefreshCw, LuWallet } from 'react-icons/lu';
import { DEFAULT_PROVIDER_OPTIONS, type ProviderOptions } from '../lib/chains';
import { formatEth, type Address } from '../lib/format';
import { useDemo, useSectionEntries, useSettledCount } from '../state/store';
import { Disclosure, Mono, Outcomes, SectionCard, StatusText } from './primitives';
import { Field } from './ui/field';

/**
 * Chain selection is a UI affordance (R10): selecting a chain selects a provider bound to it. Nothing
 * here switches chains — the two switch/add controls exist to prove the refusal (4200).
 */
export function ChainCard() {
  const demo = useDemo();
  const { registry, state, selected, account, connect, selectChain, addAdHocChain, setProviderOptions, run, recordViolation, isChainDisabled } = demo;
  const chains = useMemo(() => registry.list(), [registry, state.registryVersion]);
  const entries = useSectionEntries('chain');
  const settled = useSettledCount();
  const session = state.sessions[selected.chainId];

  // The wallet-advertised chain list is known once any provider has completed a handshake.
  const advertised = useMemo(() => {
    for (const s of Object.values(state.sessions)) if (s.supportedChainIds.length) return s.supportedChainIds;
    return undefined;
  }, [state.sessions]);
  const served = advertised ? advertised.includes(selected.chainId) : undefined;

  const [balance, setBalance] = useState<bigint | undefined>();
  const [deployed, setDeployed] = useState<boolean | undefined>();
  const refresh = useCallback(async () => {
    const entry = registry.get(selected.chainId);
    if (!entry || !account) {
      setBalance(undefined);
      setDeployed(undefined);
      return;
    }
    const [native, code] = await Promise.all([entry.publicClient.getBalance({ address: account }).catch(() => undefined), entry.publicClient.getCode({ address: account }).catch(() => undefined)]);
    setBalance(native);
    setDeployed(code === undefined ? undefined : !!code && code !== '0x');
  }, [registry, selected.chainId, account]);
  useEffect(() => {
    void refresh();
  }, [refresh, settled]);

  const readChainId = () =>
    run({ section: 'chain', label: 'Read eth_chainId', method: 'eth_chainId', noBalances: true }, async (api) => {
      const granted = await api.provider.request<string>({ method: 'eth_chainId' });
      const asNumber = Number.parseInt(granted, 16);
      api.update({ result: { granted, asNumber, configured: selected.chainId, providerChainId: api.provider.chainId } });
      if (asNumber !== selected.chainId) recordViolation('chain', 'eth_chainId differs from the configured chain', `granted ${granted} (${asNumber}) · configured ${selected.chainId}`);
      return granted;
    });

  const tryMethod = (method: 'wallet_switchEthereumChain' | 'wallet_addEthereumChain') => {
    const target = chains.find((chain) => chain.config.chainId !== selected.chainId)?.config ?? selected.config;
    const params = method === 'wallet_switchEthereumChain' ? [{ chainId: `0x${target.chainId.toString(16)}` }] : [{ chainId: `0x${target.chainId.toString(16)}`, chainName: target.name, rpcUrls: [target.rpcUrl] }];
    return run({ section: 'chain', label: `Attempt ${method} → ${target.name}`, method, params, expected: true, noBalances: true }, async (api) => {
      const result = await api.provider.request({ method, params });
      recordViolation('chain', `${method} succeeded`, `Giano binds one chain per provider; a switch or add must be refused with 4200. Result: ${JSON.stringify(result)}`);
      return result;
    });
  };

  return (
    <SectionCard
      id="chain"
      title="Chain and connection"
      description="Pick the chain to work on and connect. Selecting a chain selects a provider bound to it; nothing here switches chains."
      sdk={[
        ['createGianoWalletProvider', 'one provider per chain, over the same wallet origin'],
        ['eth_requestAccounts', 'connect: opens the wallet popup, returns the smart-account address'],
        ['eth_chainId', 'the chain the wallet granted, read back and compared with the configured one'],
        ['provider.supportedChainIds', 'which chains the wallet serves, learned from the handshake'],
        ['wallet_switchEthereumChain / wallet_addEthereumChain', 'refused with 4200 by design — developer controls below prove it'],
      ]}
    >
      <HStack gap="3" flexWrap="wrap" align="center">
        <SegmentGroup.Root size="sm" value={String(selected.chainId)} onValueChange={(details) => details.value && selectChain(Number(details.value))} data-testid="chain-selector">
          <SegmentGroup.Indicator />
          <SegmentGroup.Items
            items={chains.map((chain) => ({
              value: String(chain.config.chainId),
              disabled: isChainDisabled(chain.config.chainId),
              label: (
                <HStack gap="2">
                  <span>{chain.config.name}</span>
                  <Mono muted>{chain.config.chainId}</Mono>
                </HStack>
              ),
            }))}
          />
        </SegmentGroup.Root>
        <AddChain onAdd={addAdHocChain} />
      </HStack>

      {isChainDisabled(selected.chainId) && (
        <StatusText tone="red">This chain&apos;s RPC serves another network (see preflight). Write controls are disabled until GIANO_CHAINS is fixed.</StatusText>
      )}

      <HStack gap="6" flexWrap="wrap">
        <StatusText tone={served === undefined ? 'gray' : served ? 'green' : 'orange'}>
          {served === undefined ? 'served by the wallet: unknown until a handshake' : served ? 'served by the wallet' : `not served by the wallet (it serves ${advertised!.join(', ')})`}
        </StatusText>
        <HStack gap="2">
          <Text fontSize="sm" color="fg.muted">
            Balance
          </Text>
          <Mono size="sm">{account ? formatEth(balance) : '—'}</Mono>
          <Button size="xs" variant="ghost" colorPalette="gray" onClick={() => void refresh()} aria-label="Refresh balance">
            <LuRefreshCw />
          </Button>
        </HStack>
        <HStack gap="2">
          <Text fontSize="sm" color="fg.muted">
            Account
          </Text>
          <Text fontSize="sm">{!account ? 'not connected on this chain' : deployed === undefined ? 'deployment unknown' : deployed ? 'deployed on this chain' : 'deploys with the first transaction'}</Text>
        </HStack>
        {session?.grantedChainId && (
          <HStack gap="2">
            <Text fontSize="sm" color="fg.muted">
              Granted
            </Text>
            <Mono size="sm">{session.grantedChainId}</Mono>
          </HStack>
        )}
      </HStack>

      <HStack gap="2" flexWrap="wrap">
        <Button colorPalette="brand" onClick={() => void connect(selected.chainId)} disabled={isChainDisabled(selected.chainId)} data-testid="connect-chain">
          <LuWallet /> Connect on {selected.config.name}
        </Button>
      </HStack>

      <Disclosure label="Developer controls">
        <Stack gap="4">
          <HStack gap="2" flexWrap="wrap">
            <Button size="sm" variant="outline" onClick={() => void readChainId()} disabled={!account}>
              Read eth_chainId
            </Button>
            <Button size="sm" variant="ghost" colorPalette="gray" onClick={() => void tryMethod('wallet_switchEthereumChain')}>
              <LuLayers /> Try switchEthereumChain
            </Button>
            <Button size="sm" variant="ghost" colorPalette="gray" onClick={() => void tryMethod('wallet_addEthereumChain')}>
              <LuLayers /> Try addEthereumChain
            </Button>
            <Text fontSize="xs" color="fg.muted">
              A switch or add succeeding would be a violation.
            </Text>
          </HStack>
          <ProviderOptionsPanel chainId={selected.chainId} options={registry.optionsFor(selected.chainId)} onApply={(options) => setProviderOptions(selected.chainId, options)} />
        </Stack>
      </Disclosure>

      <Outcomes entries={entries} />
    </SectionCard>
  );
}

function AddChain({ onAdd }: { onAdd: (chainId: number, rpcUrl: string, name?: string) => void }) {
  const [chainId, setChainId] = useState('99999');
  const [rpcUrl, setRpcUrl] = useState('');
  const { config } = useDemo();
  const placeholder = config.chains[0].rpcUrl;
  return (
    <Disclosure label="Add a chain…">
      <HStack gap="3" align="flex-end" flexWrap="wrap">
        <Field label="Chain id" width="32">
          <Input size="sm" fontFamily="mono" value={chainId} onChange={(event) => setChainId(event.target.value)} />
        </Field>
        <Field label="RPC URL" helperText="A chain the wallet may not serve: connecting provokes 4902 (unserved) or 4901 (served, unreachable)." width="96">
          <Input size="sm" fontFamily="mono" value={rpcUrl} placeholder={placeholder} onChange={(event) => setRpcUrl(event.target.value)} />
        </Field>
        <Button size="sm" variant="outline" onClick={() => onAdd(Number(chainId), rpcUrl || placeholder)} disabled={!/^\d+$/.test(chainId)}>
          Add chain
        </Button>
      </HStack>
    </Disclosure>
  );
}

function ProviderOptionsPanel({ chainId, options, onApply }: { chainId: number; options: ProviderOptions; onApply: (options: ProviderOptions) => void }) {
  const [walletApiPath, setWalletApiPath] = useState(options.walletApiPath);
  const [storage, setStorage] = useState<ProviderOptions['storage']>(options.storage);
  const [sdkVersion, setSdkVersion] = useState(options.sdkVersion ?? '');
  useEffect(() => {
    setWalletApiPath(options.walletApiPath);
    setStorage(options.storage);
    setSdkVersion(options.sdkVersion ?? '');
  }, [chainId, options]);
  const dirty = walletApiPath !== options.walletApiPath || storage !== options.storage || (sdkVersion || undefined) !== options.sdkVersion;
  return (
    <Disclosure
      label={
        <>
          Provider options · <Mono muted>walletApiPath {options.walletApiPath} · {options.storage}{options.sdkVersion ? ` · sdk ${options.sdkVersion}` : ''}</Mono>
        </>
      }
    >
      <Stack gap="3">
        <Text fontSize="sm" color="fg.muted">
          Options of createGianoWalletProvider for this chain. Applying drops the current provider; the next one is built with these values.
        </Text>
        <HStack gap="4" align="flex-end" flexWrap="wrap">
          <Field label="walletApiPath" helperText="Path under the wallet origin that proxies to wallet-api." width="48">
            <Input size="sm" fontFamily="mono" value={walletApiPath} onChange={(event) => setWalletApiPath(event.target.value)} />
          </Field>
          <Field label="storage" helperText="In-memory storage disables session resume on purpose.">
            <SegmentGroup.Root size="sm" value={storage} onValueChange={(details) => details.value && setStorage(details.value as ProviderOptions['storage'])}>
              <SegmentGroup.Indicator />
              <SegmentGroup.Items items={[{ value: 'localStorage', label: 'localStorage' }, { value: 'memory', label: 'in-memory' }]} />
            </SegmentGroup.Root>
          </Field>
          <Field label="sdkVersion" helperText="Sent in the handshake; empty = the connector default." width="32">
            <Input size="sm" fontFamily="mono" value={sdkVersion} placeholder="default" onChange={(event) => setSdkVersion(event.target.value)} />
          </Field>
          <Button size="sm" variant="outline" disabled={!dirty} onClick={() => onApply({ walletApiPath: walletApiPath || DEFAULT_PROVIDER_OPTIONS.walletApiPath, storage, sdkVersion: sdkVersion || undefined })}>
            Apply to next provider
          </Button>
        </HStack>
      </Stack>
    </Disclosure>
  );
}

export type { Address };
