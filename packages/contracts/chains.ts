// The chain descriptor — the ONE configuration shape naming a chain a Giano deployment
// serves, carried identically by the wallet origin, the backend and the operator console
// (specs/MULTICHAIN_SPECS.md §3, MC-95). Each consumer validates the same core and extends
// it with what only it needs.

import { z } from 'zod';
import { gianoAddresses } from './addresses';

const addressPattern = /^0x[0-9a-fA-F]{40}$/;

export const chainAddressSchema = z
  .string()
  .regex(addressPattern, 'must be a 0x-prefixed 20-byte hex address') as z.ZodType<`0x${string}`>;

/**
 * The core every consumer shares. There is deliberately no `default` field: there is no
 * default chain anywhere in the system (MC-11). A dApp always names the chain it wants,
 * and a backend request may omit it only when exactly one chain is configured (MC-53).
 */
export const chainDescriptorSchema = z.object({
  chainId: z.number().int().positive(),
  /** Human-readable, shown to users and operators. Required — MC-81 forbids bare ids in the UI. */
  name: z.string().min(1),
  /** Read path. */
  rpcUrl: z.string().url(),
});

export type ChainDescriptor = z.infer<typeof chainDescriptorSchema>;

/** Per-chain policy defaults. Address-valued fields are never inherited across chains (MC-61). */
export const chainPolicySchema = z
  .object({
    maxCallGas: z.string().regex(/^\d+$/).optional(),
    maxVerificationGas: z.string().regex(/^\d+$/).optional(),
    maxFeePerGas: z.string().regex(/^\d+$/).optional(),
    maxPriorityFeePerGas: z.string().regex(/^\d+$/).optional(),
    allowedTargets: z.array(chainAddressSchema).optional(),
    allowedPaymasters: z.array(chainAddressSchema).optional(),
  })
  .strict();

export type ChainPolicy = z.infer<typeof chainPolicySchema>;

/**
 * wallet-api's extension: submission and the on-chain addresses it must never take from
 * a request. `entryPoint` / `factory` / `sponsorshipPaymaster` default from the contracts
 * registry for `chainId`; explicit values win.
 */
export const backendChainDescriptorSchema = chainDescriptorSchema.extend({
  bundlerUrl: z.string().url(),
  entryPoint: chainAddressSchema.optional(),
  factory: chainAddressSchema.optional(),
  sponsorshipPaymaster: chainAddressSchema.optional(),
  policy: chainPolicySchema.optional(),
});

export type BackendChainDescriptor = z.infer<typeof backendChainDescriptorSchema>;

/** wallet-web's extension: what the browser needs; it never learns an endpoint it may not use. */
export const walletChainDescriptorSchema = chainDescriptorSchema.extend({
  bundlerUrl: z.string().url(),
  factoryAddress: chainAddressSchema.optional(),
  sponsorship: z.enum(['service', 'test-paymaster', 'off']).optional(),
  paymasterServiceUrl: z.string().optional(),
  testPaymasterAddress: chainAddressSchema.optional(),
});

export type WalletChainDescriptor = z.infer<typeof walletChainDescriptorSchema>;

/**
 * Validates a list of descriptors under the rules every consumer shares (MC-42):
 * at least one entry, unique chain ids, and no privileged entry (the shape has no way to
 * express one — that is the point). Returns readable errors naming the chain and field.
 */
export function validateChainList<T extends ChainDescriptor>(descriptors: T[]): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (descriptors.length === 0) errors.push('at least one chain must be configured');
  const seenIds = new Set<number>();
  const seenNames = new Set<string>();
  for (const descriptor of descriptors) {
    if (seenIds.has(descriptor.chainId)) errors.push(`duplicate chainId ${descriptor.chainId}`);
    seenIds.add(descriptor.chainId);
    // Operators read names; two chains called "Testnet" is an incident waiting to happen.
    if (seenNames.has(descriptor.name)) warnings.push(`duplicate chain name "${descriptor.name}"`);
    seenNames.add(descriptor.name);
  }
  return { errors, warnings };
}

/** Well-known chain names, used when a single-chain shorthand supplies no name. */
const KNOWN_CHAIN_NAMES: Record<number, string> = {
  1: 'Ethereum',
  10: 'OP Mainnet',
  8453: 'Base',
  84532: 'Base Sepolia',
  11155111: 'Sepolia',
  31337: 'Local devnet A',
  31338: 'Local devnet B',
};

/** A display name for a chain: registry/known name, else "chain <id>" (never a bare number). */
export function defaultChainName(chainId: number): string {
  return KNOWN_CHAIN_NAMES[chainId] ?? `chain ${chainId}`;
}

/** True when the chain has a registry entry the descriptor's addresses may default from. */
export function hasRegistryEntry(chainId: number): boolean {
  return chainId in gianoAddresses;
}
