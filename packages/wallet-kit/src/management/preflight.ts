import { encodeAddOwnerPublicKey } from '@appliedblockchain/giano-wallet-core';
import { pad } from 'viem';
import type { SponsorshipPreflight, WalletRuntime } from '../runtimes';
import { ensureAccount } from './apply-owner-change';

/**
 * Asks the rules engine whether a wallet-management operation would be sponsored, BEFORE
 * any ceremony is started (WM-68, WK-13): a user must never be walked through a passkey
 * prompt for an operation that was already refused. The calldata is a representative
 * addOwnerPublicKey self-call — the rule is structural (a call from the wallet to
 * itself), so any management operation answers the same.
 */
export async function preflightManagement({
  runtime,
  walletAddress,
}: {
  runtime: WalletRuntime;
  walletAddress: `0x${string}`;
}): Promise<SponsorshipPreflight> {
  if (!(await ensureAccount(runtime))) {
    return { state: 'unavailable', message: 'the wallet is not connected yet' };
  }
  const zero = pad('0x00', { size: 32 });
  return runtime.checkSponsorship({ to: walletAddress, data: encodeAddOwnerPublicKey(zero, zero) });
}
