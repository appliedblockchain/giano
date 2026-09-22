import { Button, HStack, Text } from '@chakra-ui/react';
import { useState } from 'react';
import { LuKeyRound } from 'react-icons/lu';
import { useDemo, useSectionEntries } from '../state/store';
import { Outcomes, SectionCard } from './primitives';

/**
 * R15 / WM-39, WM-40: the application's entire involvement in wallet management is opening the view.
 * It passes nothing and learns nothing; anything returned is a violation.
 */
export function ManagementCard() {
  const { selected, account, run, recordViolation, isChainDisabled } = useDemo();
  const entries = useSectionEntries('management');
  const [busy, setBusy] = useState(false);

  const manage = async () => {
    setBusy(true);
    try {
      await run({ section: 'management', label: 'Manage wallet', method: 'giano_openWalletManagement', account, noBalances: true }, async (api) => {
        const returned = (await api.provider.openWalletManagement()) as unknown;
        if (returned !== undefined && returned !== null) {
          recordViolation('management', 'openWalletManagement returned data', `the application must learn nothing from the management view (WM-40); received ${JSON.stringify(returned)}`);
          return { returned };
        }
        api.update({ note: 'closed · returned undefined, as required' });
        return 'closed, no data returned';
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard
      id="management"
      title="Wallet management"
      description="Add a passkey, another device or an externally-owned account, or remove one. The application's entire involvement is opening the view: it passes nothing and learns nothing."
      sdk={[['provider.openWalletManagement()', 'opens the management view on the wallet origin; resolves with no data when closed (giano_openWalletManagement)']]}
    >
      <HStack gap="4" flexWrap="wrap">
        <Button colorPalette="brand" onClick={() => void manage()} disabled={!account || busy || isChainDisabled(selected.chainId)} loading={busy} loadingText="Management open…" data-testid="manage">
          <LuKeyRound /> Manage wallet
        </Button>
        <Text fontSize="sm" color="fg.muted">
          Add a passkey, another device or an externally-owned account, or remove one — all on the wallet origin.
        </Text>
      </HStack>
      <Outcomes entries={entries} />
    </SectionCard>
  );
}
