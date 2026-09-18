import { Button, HStack, Input, Textarea } from '@chakra-ui/react';
import { useMemo, useState } from 'react';
import { LuPenLine } from 'react-icons/lu';
import { hashMessage, toHex } from 'viem';
import { useDemo, useSectionEntries } from '../state/store';
import { ActionPicker, Disclosure, Outcomes, SectionCard } from './primitives';
import { Field } from './ui/field';

type Method = 'personal_sign' | 'eth_sign' | 'eth_signTypedData_v4';

const METHODS: Array<{ value: Method; label: string }> = [
  { value: 'personal_sign', label: 'personal_sign' },
  { value: 'eth_sign', label: 'eth_sign' },
  { value: 'eth_signTypedData_v4', label: 'eth_signTypedData_v4' },
];

/** Every signature the provider can produce, shown in full. Giano signs as a smart account: the result is an ERC-1271 blob, not v/r/s. */
export function SigningCard() {
  const { selected, account, run, isChainDisabled } = useDemo();
  const entries = useSectionEntries('signing');
  const [method, setMethod] = useState<Method>('personal_sign');
  const [message, setMessage] = useState('Hello from the Giano demo!');
  const defaultTyped = useMemo(
    () =>
      JSON.stringify(
        {
          domain: { name: 'Giano Demo', version: '1', chainId: selected.chainId },
          types: { Greeting: [{ name: 'text', type: 'string' }] },
          primaryType: 'Greeting',
          message: { text: message },
        },
        null,
        2,
      ),
    [selected.chainId, message],
  );
  const [typed, setTyped] = useState<string | null>(null);
  const typedData = typed ?? defaultTyped;
  const [busy, setBusy] = useState(false);

  const sign = async () => {
    if (!account) return;
    setBusy(true);
    try {
      if (method === 'eth_signTypedData_v4') {
        let parsed: unknown;
        try {
          parsed = JSON.parse(typedData);
        } catch (error) {
          await run({ section: 'signing', label: 'Sign typed data (invalid JSON)', method, params: [account, typedData], account, noBalances: true }, async () => {
            throw error;
          });
          return;
        }
        await run({ section: 'signing', label: 'Sign typed data', method, params: [account, parsed], account, noBalances: true }, (api) =>
          api.provider.request<string>({ method, params: [account, JSON.stringify(parsed)] }),
        );
        return;
      }
      const hex = toHex(message);
      // personal_sign takes [message, address]; eth_sign takes [address, hash-or-message]. Both recorded as sent.
      const params = method === 'personal_sign' ? [hex, account] : [account, hashMessage(message)];
      await run({ section: 'signing', label: method === 'personal_sign' ? 'Sign message' : 'eth_sign', method, params, account, noBalances: true }, (api) => api.provider.request<string>({ method, params }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard
      id="signing"
      title="Sign"
      description="Sign a message or typed data with your passkey. Giano signs as a smart account, so the result is an ERC-1271 signature, not an ECDSA v/r/s triple."
      sdk={[
        ['personal_sign', 'EIP-191 personal message signature'],
        ['eth_sign', 'raw hash signature (legacy)'],
        ['eth_signTypedData_v4', 'EIP-712 typed data signature — also what an EIP-2612 permit uses'],
      ]}
    >
      <Field label="Message">
        <Input value={message} onChange={(event) => setMessage(event.target.value)} />
      </Field>
      <HStack gap="3" align="flex-end" flexWrap="wrap">
        <Field label="Method">
          <ActionPicker label="Method" value={method} options={METHODS} onChange={setMethod} />
        </Field>
        <Button colorPalette="brand" onClick={() => void sign()} disabled={!account || busy || isChainDisabled(selected.chainId)} loading={busy} loadingText="Awaiting wallet…" data-testid="sign">
          <LuPenLine /> Sign
        </Button>
      </HStack>
      <Disclosure label="Typed data for eth_signTypedData_v4 (editable)" defaultOpen={method === 'eth_signTypedData_v4'}>
        <Textarea fontFamily="mono" fontSize="xs" rows={9} value={typedData} onChange={(event) => setTyped(event.target.value)} />
        {typed !== null && (
          <Button size="xs" variant="ghost" mt="2" onClick={() => setTyped(null)}>
            Reset to default
          </Button>
        )}
      </Disclosure>
      <Outcomes entries={entries} />
    </SectionCard>
  );
}
