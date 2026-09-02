import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex, PublicClient } from 'viem';

/**
 * On-chain owner-set reads (D1: the chain IS the owner set). Used wherever the registry
 * is about to make a claim about ownership — binding a credential to a wallet (WM-15) or
 * marking one removed (WM-31) — so registry state never asserts what the chain does not.
 *
 * `null` means the question is unanswerable there: the account has no code on that chain
 * (deployment is lazy and per chain) or the chain could not be read. Callers must treat
 * null as "unknown", never as "no".
 */

async function hasCode(client: PublicClient, address: Address): Promise<boolean> {
  const code = await client.getCode({ address }).catch(() => undefined);
  return !!code && code !== '0x';
}

export async function isOwnerPublicKeyOnChain(client: PublicClient, wallet: Address, x: Hex, y: Hex): Promise<boolean | null> {
  try {
    if (!(await hasCode(client, wallet))) return null;
    return await client.readContract({
      address: wallet,
      abi: gianoSmartWalletAbi,
      functionName: 'isOwnerPublicKey',
      args: [x, y],
    });
  } catch {
    return null;
  }
}

export async function isOwnerAddressOnChain(client: PublicClient, wallet: Address, owner: Address): Promise<boolean | null> {
  try {
    if (!(await hasCode(client, wallet))) return null;
    return await client.readContract({
      address: wallet,
      abi: gianoSmartWalletAbi,
      functionName: 'isOwnerAddress',
      args: [owner],
    });
  } catch {
    return null;
  }
}
