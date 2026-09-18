import { Text } from '@chakra-ui/react';
import { CONNECTOR_VERSION } from '../config';
import { useDemo } from '../state/store';
import { KeyValues, SectionCard } from './primitives';

/** What this instance is pointed at: the runtime configuration, in plain terms. */
export function SetupInfoCard() {
  const { config, registry, state } = useDemo();
  return (
    <SectionCard
      id="setup-info"
      title="This instance"
      description="The runtime configuration the container injected at start. One image serves every deployment; only these values differ."
      sdk={[
        ['createGianoWalletProvider({ walletUrl, chain, transport, walletApiPath, storage })', 'one provider is built per chain from these values, lazily, on first use'],
        ['provider.supportedChainIds', 'the chains the wallet advertised in the handshake (known after the first connect)'],
      ]}
    >
      <KeyValues
        items={[
          ['this app', window.location.origin],
          ['wallet origin', registry.walletOrigin],
          ['tenant label', config.appLabel],
          ['chains', config.chains.map((chain) => `${chain.name} (${chain.chainId})`).join(' · ')],
          ['other tenant wallet', config.otherWalletUrl ? new URL(config.otherWalletUrl).origin : 'not configured (disallowed-origin control hidden)'],
          ['connector', CONNECTOR_VERSION],
          ['wallet-api', state.preflight?.walletApiVersion ?? 'unknown until preflight'],
        ]}
      />
      <Text fontSize="xs" color="fg.muted">
        Variables: GIANO_WALLET_URL, GIANO_CHAINS, GIANO_OTHER_WALLET_URL, GIANO_APP_LABEL, GIANO_RPC_UPSTREAM_&lt;chainId&gt;. See the README for the full contract.
      </Text>
    </SectionCard>
  );
}
