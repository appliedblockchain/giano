import { Badge, Button, HStack, Stack, Text } from '@chakra-ui/react';
import { useCallback, useEffect, useState } from 'react';
import { LuSend } from 'react-icons/lu';
import { demoChains, providerFor, publicClientFor } from '../giano';
import type { DemoChain } from '../config';
import { notifyError, notifySuccess } from '../lib/notify';
import { shortAddress } from '../lib/errors';
import { ResultBox } from './ResultBox';
import { SectionCard } from './SectionCard';

type Address = `0x${string}`;

type Outcome = { tone: 'accent' | 'error'; label: string; value: string } | null;

/**
 * Cross-chain submission, first-class (MC-124): pick a chain, submit, see which chain it
 * landed on and the receipt. The account address is shown BESIDE the selected chain and
 * visibly does not change as the selection changes — one passkey, one address, every
 * served chain (MC-16, MC-125). Rendered only when more than one chain is configured, so
 * a single-chain deployment never sees a picker (MC-89).
 *
 * The panel holds one provider per chain, constructed once and selected by the picker.
 * Switching the selector switches PROVIDER — it does not switch a chain, because providers
 * do not switch chains (D1). That distinction is the thing an integrator most needs to
 * take away from this demo.
 */
export function CrossChainPanel({ account }: { account: Address }) {
  const [selected, setSelected] = useState<DemoChain>(demoChains[0]);
  const [deployed, setDeployed] = useState<Record<number, boolean | null>>({});
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>(null);

  const refreshDeployment = useCallback(async () => {
    const entries = await Promise.all(
      demoChains.map(async (demoChain) => {
        try {
          const code = await publicClientFor(demoChain).getCode({ address: account });
          return [demoChain.chainId, !!code && code !== '0x'] as const;
        } catch {
          return [demoChain.chainId, null] as const;
        }
      }),
    );
    setDeployed(Object.fromEntries(entries));
  }, [account]);

  useEffect(() => {
    void refreshDeployment();
  }, [refreshDeployment]);

  const send = useCallback(async () => {
    setBusy(true);
    setOutcome(null);
    try {
      const chainProvider = providerFor(selected);
      // A provider that has not connected yet negotiates its own session for its own
      // chain — same passkey, one sign-in ceremony, no re-registration (MC-77).
      const accounts = await chainProvider.request<string[]>({ method: 'eth_requestAccounts' });
      const sender = accounts?.[0] as Address;
      const hash = await chainProvider.request<string>({
        method: 'eth_sendTransaction',
        params: [{ to: sender, value: '0x0' }],
      });
      const receipt = await chainProvider.request<{ success: boolean; receipt?: { transactionHash?: string } }>({
        method: 'waitForUserOperationReceipt',
        params: [hash],
      });
      // Success and failure alike land on screen AND in the console (MC-126).
      const summary = `chain ${selected.chainId} (${selected.name}) · sender ${sender} · userOp ${hash} · success ${receipt.success}`;
      console.info('[giano-demo] cross-chain submission', { chainId: selected.chainId, sender, userOpHash: hash, receipt });
      setOutcome({
        tone: receipt.success ? 'accent' : 'error',
        label: `Landed on ${selected.name} (chain ${selected.chainId})`,
        value: summary,
      });
      notifySuccess(`Transaction on ${selected.name}`, `userOp ${shortAddress(hash)} · success ${receipt.success}`);
      await refreshDeployment();
    } catch (error) {
      const message = notifyError(`Transaction on ${selected.name} failed`, error);
      setOutcome({ tone: 'error', label: `Failed on ${selected.name} (chain ${selected.chainId})`, value: message });
    } finally {
      setBusy(false);
    }
  }, [selected, refreshDeployment]);

  if (demoChains.length < 2) return null;

  return (
    <SectionCard
      title="Cross-chain"
      description="One passkey, one address, several chains — the dApp picks the chain per provider"
    >
      <Stack gap="4">
        <HStack gap="2" flexWrap="wrap" data-testid="chain-selector">
          {demoChains.map((demoChain) => (
            <Button
              key={demoChain.chainId}
              size="sm"
              variant={selected.chainId === demoChain.chainId ? 'solid' : 'outline'}
              colorPalette="brand"
              onClick={() => setSelected(demoChain)}
              data-testid={`chain-option-${demoChain.chainId}`}
            >
              {demoChain.name} · {demoChain.chainId}
            </Button>
          ))}
        </HStack>

        <HStack gap="3" flexWrap="wrap">
          <Text fontSize="sm" color="fg.muted">
            Your address on {selected.name}:
          </Text>
          {/* Deliberately the SAME value whatever chain is selected — that is the point (MC-125). */}
          <Badge colorPalette="accent" fontFamily="mono" data-testid="cross-chain-address">
            {account}
          </Badge>
          <Badge
            colorPalette={deployed[selected.chainId] ? 'green' : 'gray'}
            variant="subtle"
            data-testid={`deployment-${selected.chainId}`}
          >
            {deployed[selected.chainId] === null || deployed[selected.chainId] === undefined
              ? 'deployment status unavailable'
              : deployed[selected.chainId]
                ? 'deployed on this chain'
                : 'deploys with your first transaction here'}
          </Badge>
        </HStack>

        <HStack>
          <Button colorPalette="brand" onClick={send} loading={busy} loadingText="Submitting…" data-testid="cross-chain-send">
            <LuSend /> Send 0 ETH to self on {selected.name}
          </Button>
        </HStack>

        {outcome && <ResultBox label={outcome.label} value={outcome.value} tone={outcome.tone} />}
      </Stack>
    </SectionCard>
  );
}
