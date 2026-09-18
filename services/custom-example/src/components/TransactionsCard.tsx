import { Button, HStack, Input, SegmentGroup, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useState } from 'react';
import { LuFuel, LuRefreshCw, LuSend } from 'react-icons/lu';
import { getAddress, isAddress, isHex, parseEther, toHex } from 'viem';
import { formatEth, type Address, type Hex } from '../lib/format';
import type { Payer } from '../lib/receipt';
import { submitTransaction, waitForReceipt } from '../lib/run';
import { useDemo, useSectionEntries, useSettledCount } from '../state/store';
import { ActionPicker, Mono, Outcomes, SectionCard, StatusText } from './primitives';
import { ClipboardIconButton, ClipboardRoot } from './ui/clipboard';
import { Field } from './ui/field';

type Preset = 'self' | 'value' | 'unlisted' | 'custom';

const PRESETS: Array<{ value: Preset; label: string }> = [
  { value: 'self', label: 'Send 0 ETH to self' },
  { value: 'value', label: 'Send value to an address' },
  { value: 'unlisted', label: 'Call an unlisted contract (refusal expected)' },
  { value: 'custom', label: 'Arbitrary target + calldata' },
];

/** A contract no tenant allow-lists, called with a valid-looking selector: reaches the paymaster's allowlist rule and is refused by it. */
const UNLISTED: Address = '0x000000000000000000000000000000000000dEaD';
const TRANSFER_SELECTOR: Hex = '0xa9059cbb';

/**
 * R12/D5: the user declares the expected payer; the receipt says who paid; a disagreement stays flagged.
 * R7: refusal and insufficient balance are first-class outcomes, not omissions.
 */
export function TransactionsCard() {
  const { state, selected, account, run, isChainDisabled } = useDemo();
  const entries = useSectionEntries('transactions');
  const [preset, setPreset] = useState<Preset>('self');
  const [payer, setPayer] = useState<Payer>('sponsored');
  const [to, setTo] = useState('');
  const [value, setValue] = useState('0');
  const [data, setData] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (preset === 'self' && account) setTo(account);
    if (preset === 'unlisted') {
      setTo(UNLISTED);
      setData(TRANSFER_SELECTOR);
      setValue('0');
    }
  }, [preset, account]);

  const disabled = !account || busy || isChainDisabled(selected.chainId);
  const receiptsAtRisk = state.preflight?.receiptsAtRisk ?? false;

  const send = async () => {
    if (!account) return;
    if (!isAddress(to)) {
      await run({ section: 'transactions', label: 'Send (invalid address)', method: 'eth_sendTransaction', params: [{ to }], account, noBalances: true }, async () => {
        throw new Error(`"${to}" is not a valid address — refused before reaching the wallet`);
      });
      return;
    }
    if (data && !isHex(data)) {
      await run({ section: 'transactions', label: 'Send (invalid calldata)', method: 'eth_sendTransaction', params: [{ to, data }], account, noBalances: true }, async () => {
        throw new Error(`calldata "${data}" is not hex — refused before reaching the wallet`);
      });
      return;
    }
    const tx = { to: getAddress(to), value: toHex(parseEther(value || '0')), ...(data ? { data: data as Hex } : {}) };
    setBusy(true);
    try {
      await run(
        { section: 'transactions', label: PRESETS.find((option) => option.value === preset)!.label, method: 'eth_sendTransaction', params: [tx], account, declaredPayer: payer, expected: preset === 'unlisted', sponsoredSend: payer === 'sponsored' },
        (api) => submitTransaction(api, tx),
      );
    } finally {
      setBusy(false);
    }
  };

  const keepWaiting = (hash: string) =>
    run({ section: 'transactions', label: 'Keep waiting for receipt', method: 'waitForUserOperationReceipt', params: [hash], account, declaredPayer: payer }, (api) => waitForReceipt(api, hash));
  const timedOut = entries.find((entry) => entry.status === 'timed-out' && entry.userOpHash);

  return (
    <SectionCard
      id="transactions"
      title="Send"
      description="Send value or call a contract. Declare who you expect to pay for gas; the receipt says who did, and a disagreement stays flagged on the entry."
      sdk={[
        ['eth_sendTransaction', 'the wallet builds, sponsors (or not), signs with the passkey and submits a user operation; returns its hash'],
        ['waitForUserOperationReceipt', 'polls the wallet origin\'s public receipt endpoint; the receipt carries the paymaster that paid'],
        ['publicClient.getBalance', 'native balance before and after, read dApp-side'],
      ]}
    >
      <HStack gap="4" align="flex-end" flexWrap="wrap">
        <Field label="Action">
          <ActionPicker label="Action" value={preset} options={PRESETS} onChange={setPreset} />
        </Field>
        <Field label="Gas payer" helperText={payer === 'sponsored' ? "The wallet's paymaster covers the fee; the receipt carries a paymaster address." : 'Needs native balance on this chain; refusals and AA21 errors are recorded in full.'}>
          <SegmentGroup.Root size="sm" value={payer} onValueChange={(details) => details.value && setPayer(details.value as Payer)} data-testid="payer">
            <SegmentGroup.Indicator />
            <SegmentGroup.Items items={[{ value: 'sponsored', label: 'Sponsored by the app' }, { value: 'self-paid', label: 'Paid by this account' }]} />
          </SegmentGroup.Root>
        </Field>
      </HStack>

      {(preset === 'value' || preset === 'custom') && (
        <HStack gap="3" align="flex-start" flexWrap="wrap">
          <Field label="To" flex="2" minW="64">
            <Input fontFamily="mono" value={to} placeholder="0x…" onChange={(event) => setTo(event.target.value)} />
          </Field>
          <Field label="Value (ETH)" w="32">
            <Input fontFamily="mono" value={value} onChange={(event) => setValue(event.target.value)} />
          </Field>
          {preset === 'custom' && (
            <Field label="Calldata (hex)" flex="1" minW="48">
              <Input fontFamily="mono" value={data} placeholder="0x" onChange={(event) => setData(event.target.value)} />
            </Field>
          )}
        </HStack>
      )}
      {preset === 'self' && (
        <Text fontSize="sm" color="fg.muted">
          Sends 0 ETH to your own account: the simplest possible operation, sponsored as wallet management by the platform.
        </Text>
      )}
      {preset === 'unlisted' && (
        <Text fontSize="sm" color="fg.muted">
          Calls a contract no tenant allow-lists. The wallet refuses sponsorship before asking for your passkey; closing the popup returns 4001 here.
        </Text>
      )}

      <HStack gap="4" flexWrap="wrap">
        <Button colorPalette="brand" onClick={() => void send()} disabled={disabled} loading={busy} loadingText="Awaiting wallet…" data-testid="send">
          <LuSend /> Send
        </Button>
        <BalanceAndFunding />
      </HStack>

      {receiptsAtRisk && <StatusText tone="orange">The wallet origin did not answer this origin&apos;s fetch (preflight): a send may succeed but its receipt will not be readable from here.</StatusText>}
      {timedOut && (
        <HStack gap="3">
          <StatusText tone="orange">A receipt did not arrive within the connector&apos;s deadline.</StatusText>
          <Button size="xs" variant="outline" onClick={() => void keepWaiting(timedOut.userOpHash!)}>
            <LuRefreshCw /> Keep waiting for {timedOut.userOpHash!.slice(0, 10)}…
          </Button>
        </HStack>
      )}

      <Outcomes entries={entries} />
    </SectionCard>
  );
}

/** Native balance with refresh, and the devnet funding affordance that hides itself when the node refuses. */
export function BalanceAndFunding() {
  const { registry, selected, account, run } = useDemo();
  const settled = useSettledCount();
  const [balance, setBalance] = useState<bigint | undefined>();
  const [faucet, setFaucet] = useState<'unknown' | 'available' | 'unavailable'>('unknown');
  const entry = registry.get(selected.chainId);

  const refresh = useCallback(async () => {
    if (!entry || !account) return setBalance(undefined);
    setBalance(await entry.publicClient.getBalance({ address: account }).catch(() => undefined));
  }, [entry, account]);
  useEffect(() => {
    void refresh();
  }, [refresh, settled]);
  useEffect(() => {
    setFaucet('unknown');
  }, [selected.chainId]);

  const fund = () =>
    run({ section: 'transactions', label: 'Fund from devnet', method: 'anvil_setBalance', params: [account, '0x8ac7230489e80000'], account, noBalances: false }, async (api) => {
      try {
        // A development-node method: on anything but a devnet it does not exist, and the control hides.
        const result = await api.entry.publicClient.request({ method: 'anvil_setBalance', params: [account, '0x8ac7230489e80000'] } as never);
        setFaucet('available');
        return result ?? 'balance set to 10 ETH';
      } catch (error) {
        setFaucet('unavailable');
        throw error;
      }
    });

  if (!account) return null;
  return (
    <HStack gap="2" flexWrap="wrap">
      <Text fontSize="sm" color="fg.muted">
        Balance on {selected.config.name}
      </Text>
      <Mono size="sm">{formatEth(balance)}</Mono>
      <Button size="xs" variant="ghost" colorPalette="gray" onClick={() => void refresh()} aria-label="Refresh balance">
        <LuRefreshCw />
      </Button>
      {faucet !== 'unavailable' ? (
        <Button size="sm" variant="ghost" colorPalette="gray" onClick={() => void fund()}>
          <LuFuel /> Fund from devnet
        </Button>
      ) : (
        <HStack gap="1">
          <Text fontSize="xs" color="fg.muted">
            Fund this address from a faucet for {selected.config.name}:
          </Text>
          <Mono muted>{account}</Mono>
          <ClipboardRoot value={account}>
            <ClipboardIconButton aria-label="Copy address" variant="ghost" size="2xs" />
          </ClipboardRoot>
        </HStack>
      )}
    </HStack>
  );
}

