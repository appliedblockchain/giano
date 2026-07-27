import { createGianoWalletProvider } from '@appliedblockchain/giano-connector';
import { createPublicClient, http } from 'viem';
import { chain, config } from './config';

// The thin two-origin provider: all wallet trust (passkeys, signing, consent) lives on
// the wallet origin popup — this dApp bundle ships no WebAuthn, credential or bundler code.
export const provider = createGianoWalletProvider({
  walletUrl: config.walletUrl,
  chain,
  transport: http(config.rpcUrl),
});

// Read path (balances, metadata, allowances) is answered dApp-side, no popup.
export const publicClient = createPublicClient({ chain, transport: http(config.rpcUrl) });
