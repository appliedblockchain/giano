import type { Hex } from 'viem';

/**
 * Comprehensive storage interface for Giano provider and injection data
 */
export type GianoStorage = {
  // Provider session management
  getCredentialId(): Promise<string | null>;
  setCredentialId(id: string): Promise<void>;
  getAccountAddress(): Promise<string | null>;
  setAccountAddress(address: string): Promise<void>;

  // Passkey management
  getPasskeyId(): Promise<string | null>;
  setPasskeyId(id: string): Promise<void>;
  getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null>;
  setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void>;

  // Storage management
  clear(): Promise<void>;
  isAvailable(): boolean;
};