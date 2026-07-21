/**
 * @deprecated Embedded mode makes YOUR application the wallet: your origin becomes the
 * WebAuthn relying party and your bundle carries the credential and signing code. New
 * integrations should use the thin SDK (the package's default entry point) together
 * with a deployed Giano wallet origin. This compat surface is kept for at least two
 * minor releases of 1.x — see the migration guide in the README.
 */
let warned = false;
if (!warned) {
  warned = true;
  // eslint-disable-next-line no-console
  console.warn(
    '[giano] @appliedblockchain/giano-connector/embedded is deprecated: migrate to the thin SDK (createGianoWalletProvider) — see the package README.',
  );
}

export * from '@appliedblockchain/giano-wallet-core';
export * from './connector';
export * from './gianoWallet';
