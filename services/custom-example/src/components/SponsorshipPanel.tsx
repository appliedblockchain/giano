import { useState } from 'react';
import { Button, List, Stack, Text } from '@chakra-ui/react';
import { LuBan, LuFuel } from 'react-icons/lu';
import { provider } from '../giano';
import { notifyError, notifyInfo, notifySuccess } from '../lib/notify';
import { ResultBox } from './ResultBox';
import { SectionCard } from './SectionCard';

// A contract no tenant allow-lists, called with a valid-looking `transfer(address,uint256)`
// selector. The call has to be structurally valid, not meaningful: the point is to reach the
// paymaster's allowlist rule and be refused by it. `0x…dEaD` is guaranteed never to be sponsored.
const UNLISTED_CONTRACT = '0x000000000000000000000000000000000000dEaD' as const;
const TRANSFER_SELECTOR = '0xa9059cbb' as const;

/**
 * Demonstrates Giano's paymaster (gasless sponsorship) as a first-class capability.
 *
 * The wallet origin runs an ERC-7677 sponsorship check *before* it shows an approve button, so the
 * two outcomes both surface in the popup: an allow-listed call is covered and can be approved with a
 * passkey; a call nobody sponsors is refused with a reason, no approve button, and no passkey prompt
 * — and nothing is charged. The sends elsewhere on this page take the covered path; the button here
 * is the refusal path, the half a bring-your-own wallet UI has to handle separately.
 */
export function SponsorshipPanel() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState('');
  const [error, setError] = useState('');

  const callUnlisted = async () => {
    setBusy(true);
    setResult('');
    setError('');
    try {
      const hash = await provider.request<string>({
        method: 'eth_sendTransaction',
        params: [{ to: UNLISTED_CONTRACT, value: '0x0', data: TRANSFER_SELECTOR }],
      });
      // Reaching here means the wallet found a way to sponsor (or fall back to) the call after all,
      // rather than refusing it — surface the hash so that outcome is visible too.
      setResult(`userOp: ${hash}`);
      notifyInfo('Transaction submitted', `userOp ${hash}`);
      const receipt = await provider.request<{ success: boolean }>({ method: 'waitForUserOperationReceipt', params: [hash] });
      setResult(`userOp: ${hash}\nsuccess: ${receipt.success}`);
      if (receipt.success) notifySuccess('Transaction confirmed');
    } catch (err) {
      // The expected path: the wallet refused sponsorship before approval, so closing the popup
      // rejects the request here. That is the demo working, not a failure of this dApp.
      setError(notifyError('Sponsorship refused (expected)', err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard title="Gasless sponsorship" description="Giano's paymaster covers gas — no ETH in the smart account.">
      <Stack gap="5">
        <Stack gap="1">
          <Text fontSize="sm" color="fg.muted">
            Every transaction above is sponsored by Giano's paymaster: the wallet origin checks sponsorship (ERC-7677) before it
            asks for a passkey, so an allow-listed call shows as <b>covered</b> and a call nobody sponsors is <b>refused</b> up
            front — no approval, no passkey prompt, nothing charged.
          </Text>
          <List.Root fontSize="sm" color="fg.muted" ps="4">
            <List.Item>
              <b>Send 0 ETH to self</b> — wallet management, sponsored even with nothing about the wallet allow-listed.
            </List.Item>
            <List.Item>
              <b>Transfer / approve</b> the demo ERC-20 — an allow-listed contract call, the everyday sponsored path.
            </List.Item>
            <List.Item>
              <b>Call an unlisted contract</b> (below) — the refusal path, shown in the popup before approval.
            </List.Item>
          </List.Root>
        </Stack>

        <Stack gap="1">
          <Text fontWeight="medium">Trigger a sponsorship refusal</Text>
          <Text fontSize="sm" color="fg.muted">
            Sends a call to a contract no tenant allow-lists. The wallet displays the refusal reason instead of an approve
            button; closing it rejects the request here.
          </Text>
          <Button
            mt="2"
            variant="outline"
            colorPalette="brand"
            onClick={callUnlisted}
            loading={busy}
            loadingText="Awaiting wallet…"
            alignSelf="flex-start"
          >
            {error ? <LuBan /> : <LuFuel />} Call an unlisted contract
          </Button>
          {result && <ResultBox label="Transaction" value={result} />}
          {error && <ResultBox label="Sponsorship" value={error} tone="error" />}
        </Stack>
      </Stack>
    </SectionCard>
  );
}
