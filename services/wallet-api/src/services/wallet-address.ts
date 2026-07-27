import { gianoSmartWalletFactoryAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex, PublicClient } from 'viem';
import { concat } from 'viem';

/**
 * Computes the counterfactual smart wallet address for a P-256 owner key by asking
 * the factory contract itself (`getAddress(owners, nonce)`), which is exactly how the
 * connector's `toGianoSmartAccount` resolves it client-side — same source of truth,
 * no derivation drift possible. Covered by a cross-check test against the connector.
 */
export async function computeWalletAddress(
  client: PublicClient,
  factoryAddress: Address,
  publicKeyX: Hex,
  publicKeyY: Hex,
  nonce = 0n,
): Promise<Address> {
  const ownerBytes = concat([publicKeyX, publicKeyY]); // 64-byte x||y — the WebAuthn owner encoding
  return client.readContract({
    address: factoryAddress,
    abi: gianoSmartWalletFactoryAbi,
    functionName: 'getAddress',
    args: [[ownerBytes], nonce],
  });
}
