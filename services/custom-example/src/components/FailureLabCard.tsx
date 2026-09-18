import { Button, SimpleGrid, Stack, Text } from '@chakra-ui/react';
import { useState } from 'react';
import { LuFlaskConical } from 'react-icons/lu';
import type { Address } from '../lib/format';
import { useDemo, useSectionEntries } from '../state/store';
import { Outcomes, SectionCard } from './primitives';

/**
 * R7: each control provokes one failure path on purpose and records the typed error — class, code,
 * message, data — with what it means and what to do about it.
 */
export function FailureLabCard() {
  const { config, registry, selected, account, run, revoke, addAdHocChain, recordViolation, isChainDisabled } = useDemo();
  const entries = useSectionEntries('failure-lab', 6);
  const [busy, setBusy] = useState<string | null>(null);
  const wrap = (key: string, fn: () => Promise<unknown>) => async () => {
    setBusy(key);
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  };

  /** The wallet call fires 1.5 s after the click, once the user gesture has expired: POPUP_BLOCKED. */
  const popupBlocked = wrap('popup', () =>
    run({ section: 'failure-lab', label: 'Delayed connect (popup blocked expected)', method: 'eth_requestAccounts', chainId: selected.chainId, expected: true, noBalances: true }, async (api) => {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const accounts = await api.provider.request<string[]>({ method: 'eth_requestAccounts' });
      api.update({ note: 'the browser allowed the popup outside a user gesture; recorded as-is' });
      return accounts;
    }),
  );

  /** A chain the wallet does not serve: refused in the handshake with 4902, before any passkey prompt. */
  const unserved = wrap('unserved', async () => {
    const chainId = 99_999;
    if (!registry.get(chainId)) addAdHocChain(chainId, config.chains[0].rpcUrl, 'unserved (99999)');
    await run({ section: 'failure-lab', label: 'Connect on chain 99999 (4902 expected)', method: 'eth_requestAccounts', chainId, expected: true, noBalances: true }, async (api) => {
      const accounts = await api.provider.request<string[]>({ method: 'eth_requestAccounts' });
      recordViolation('failure-lab', 'the wallet granted an unserved chain', `chain 99999 connected: ${JSON.stringify(accounts)}`, chainId);
      return accounts;
    });
  });

  /** A provider against the OTHER tenant's wallet origin, which does not allow-list this dApp: origin-not-allowed. */
  const disallowedOrigin = wrap('origin', () =>
    run(
      { section: 'failure-lab', label: `Connect via ${config.otherWalletUrl} (origin-not-allowed expected)`, method: 'eth_requestAccounts', chainId: selected.chainId, params: { walletUrl: config.otherWalletUrl }, expected: true, noBalances: true },
      async () => {
        const foreign = registry.foreignProvider(config.otherWalletUrl!, selected.chainId);
        try {
          const accounts = await foreign.request<string[]>({ method: 'eth_requestAccounts' });
          recordViolation('failure-lab', 'a wallet origin that does not allow-list this dApp accepted the connection', `${config.otherWalletUrl} granted ${JSON.stringify(accounts)}`);
          return accounts;
        } finally {
          foreign.disconnect();
        }
      },
    ),
  );

  /** Send 0 ETH; the user chooses Reject in the wallet → 4001. */
  const rejectInWallet = wrap('reject', () =>
    run({ section: 'failure-lab', label: 'Send 0 ETH to self — choose Reject in the wallet', method: 'eth_sendTransaction', params: [{ to: account, value: '0x0' }], chainId: selected.chainId, account, expected: true, noBalances: true }, (api) =>
      api.provider.request<string>({ method: 'eth_sendTransaction', params: [{ to: account, value: '0x0' }] }),
    ),
  );

  const invalidAddress = wrap('addr', () =>
    run({ section: 'failure-lab', label: 'Send to 0x1234 (invalid address)', method: 'eth_sendTransaction', params: [{ to: '0x1234', value: '0x0' }], chainId: selected.chainId, account, expected: true, noBalances: true }, (api) =>
      api.provider.request<string>({ method: 'eth_sendTransaction', params: [{ to: '0x1234' as Address, value: '0x0' }] }),
    ),
  );

  const invalidHex = wrap('hex', () =>
    run({ section: 'failure-lab', label: 'Send with data "hello" (invalid hex)', method: 'eth_sendTransaction', params: [{ to: account, data: 'hello' }], chainId: selected.chainId, account, expected: true, noBalances: true }, (api) =>
      api.provider.request<string>({ method: 'eth_sendTransaction', params: [{ to: account, value: '0x0', data: 'hello' }] }),
    ),
  );

  const disabled = isChainDisabled(selected.chainId);
  const controls: Array<{ key: string; title: string; description: string; label: string; onClick: () => Promise<void>; needsAccount?: boolean; hidden?: boolean }> = [
    { key: 'popup', title: 'Popup blocked', description: 'Issues the wallet call 1.5 s after the click, once the user gesture has expired.', label: 'Delayed connect', onClick: popupBlocked },
    { key: 'unserved', title: 'Unserved chain', description: 'Connects a provider for chain 99999 over the same wallet origin. Refused in the handshake, no passkey prompt.', label: 'Connect on 99999', onClick: unserved },
    {
      key: 'origin',
      title: 'Disallowed origin',
      description: config.otherWalletUrl ? `Connects against ${new URL(config.otherWalletUrl).host}, which does not allow-list this dApp.` : 'Set GIANO_OTHER_WALLET_URL to enable.',
      label: 'Connect via other tenant',
      onClick: disallowedOrigin,
      hidden: !config.otherWalletUrl,
    },
    { key: 'reject', title: 'User rejection', description: 'Send 0 ETH, then choose Reject in the wallet: 4001.', label: 'Send and reject', onClick: rejectInWallet, needsAccount: true },
    { key: 'revoke', title: 'Revoke, then read', description: 'wallet_revokePermissions followed by eth_accounts, which must answer [].', label: 'Revoke + eth_accounts', onClick: wrap('revoke', () => revoke()), needsAccount: true },
    { key: 'addr', title: 'Invalid address', description: 'eth_sendTransaction to 0x1234.', label: 'Send to 0x1234', onClick: invalidAddress, needsAccount: true },
    { key: 'hex', title: 'Invalid calldata', description: 'eth_sendTransaction with data "hello".', label: 'Send bad hex', onClick: invalidHex, needsAccount: true },
  ];

  return (
    <SectionCard
      id="failure-lab"
      title="Failure lab"
      description="Each control provokes one failure path on purpose and records the typed error: class, code, message, data."
      sdk={[
        ['TransportError · POPUP_BLOCKED', 'the browser refused the popup (no user gesture, or a COOP header)'],
        ['UnsupportedChainError · 4902', 'the wallet does not serve the requested chain; carries supportedChainIds'],
        ['HandshakeRefusedError · origin-not-allowed', 'this dApp origin is not in the tenant\'s allow-list'],
        ['TransportRpcError · 4001', 'rejected by the user — or refused in the wallet before approval'],
        ['wallet_revokePermissions', 'drops the session; eth_accounts must answer [] afterwards'],
      ]}
    >
      <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} gap="3">
        {controls
          .filter((control) => !control.hidden)
          .map((control) => (
            <Stack key={control.key} gap="2" p="4" borderWidth="1px" rounded="l2">
              <Text fontSize="sm" fontWeight="medium">
                {control.title}
              </Text>
              <Text fontSize="xs" color="fg.muted">
                {control.description}
              </Text>
              <Button size="sm" variant="outline" alignSelf="flex-start" onClick={() => void control.onClick()} disabled={disabled || (control.needsAccount && !account) || busy !== null} loading={busy === control.key} data-testid={`lab-${control.key}`}>
                <LuFlaskConical /> {control.label}
              </Button>
            </Stack>
          ))}
      </SimpleGrid>
      <Outcomes entries={entries} />
    </SectionCard>
  );
}
