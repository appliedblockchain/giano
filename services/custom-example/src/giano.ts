import { createGianoWalletProvider, type GianoWalletProvider } from '@appliedblockchain/giano-connector';
import { createPublicClient, http, type PublicClient } from 'viem';
import { chain, config, demoChains, type DemoChain } from './config';

// The thin two-origin provider: all wallet trust (passkeys, signing, consent) lives on
// the wallet origin popup — this dApp bundle ships no WebAuthn, credential or bundler code.
export const provider = createGianoWalletProvider({
  walletUrl: config.walletUrl,
  chain,
  transport: http(config.rpcUrl),
});

// Read path (balances, metadata, allowances) is answered dApp-side, no popup.
export const publicClient = createPublicClient({ chain, transport: http(config.rpcUrl) });

/**
 * One provider PER CHAIN, all over the same wallet origin: a provider is bound to one
 * chain for its life (MC-01), so addressing another chain means another provider — never
 * a switch (D1). This is the distinction an integrator most needs to understand, made
 * visible in the cross-chain panel.
 */
const providers = new Map<number, GianoWalletProvider>([[chain.id, provider]]);
const publicClients = new Map<number, PublicClient>([[chain.id, publicClient]]);

export function providerFor(demoChain: DemoChain): GianoWalletProvider {
  let existing = providers.get(demoChain.chainId);
  if (!existing) {
    existing = createGianoWalletProvider({
      walletUrl: config.walletUrl,
      chain: demoChain.chain,
      transport: http(demoChain.rpcUrl),
    });
    providers.set(demoChain.chainId, existing);
  }
  return existing;
}

export function publicClientFor(demoChain: DemoChain): PublicClient {
  let existing = publicClients.get(demoChain.chainId);
  if (!existing) {
    existing = createPublicClient({ chain: demoChain.chain, transport: http(demoChain.rpcUrl) });
    publicClients.set(demoChain.chainId, existing);
  }
  return existing;
}

export { demoChains };
