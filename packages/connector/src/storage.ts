import type { Hash, Hex } from 'viem';

/**
 * Comprehensive storage interface for Giano provider and injection data
 */
export interface GianoStorage {
  // Provider session management
  getCredentialId(): Promise<string | null>;
  setCredentialId(id: string): Promise<void>;
  getAccountAddress(): Promise<string | null>;
  setAccountAddress(address: string): Promise<void>;

  // Passkey management
  getPasskeyId(): Promise<string | null>;
  setPasskeyId(id: string): Promise<void>;
  getPublicKey(idHash: Hash): Promise<{ x: Hex; y: Hex } | null>;
  setPublicKey(idHash: Hash, coords: { x: Hex; y: Hex }): Promise<void>;

  // Storage management
  clear(): Promise<void>;
  isAvailable(): boolean;
}

/**
 * localStorage-based implementation
 */
export class LocalStorage implements GianoStorage {
  private isStorageAvailable(): boolean {
    try {
      return typeof window !== 'undefined' && window.localStorage !== null;
    } catch {
      return false;
    }
  }

  isAvailable(): boolean {
    return this.isStorageAvailable();
  }

  // Provider session management
  async getCredentialId(): Promise<string | null> {
    if (!this.isStorageAvailable()) return null;
    try {
      return localStorage.getItem('giano_credential_id');
    } catch {
      return null;
    }
  }

  async setCredentialId(id: string): Promise<void> {
    if (!this.isStorageAvailable()) return;
    try {
      localStorage.setItem('giano_credential_id', id);
    } catch {
      // Silently fail
    }
  }

  async getAccountAddress(): Promise<string | null> {
    if (!this.isStorageAvailable()) return null;
    try {
      return localStorage.getItem('giano_account_address');
    } catch {
      return null;
    }
  }

  async setAccountAddress(address: string): Promise<void> {
    if (!this.isStorageAvailable()) return;
    try {
      localStorage.setItem('giano_account_address', address);
    } catch {
      // Silently fail
    }
  }

  // Passkey management
  async getPasskeyId(): Promise<string | null> {
    if (!this.isStorageAvailable()) return null;
    try {
      return localStorage.getItem('gpk-passkey-id');
    } catch {
      return null;
    }
  }

  async setPasskeyId(id: string): Promise<void> {
    if (!this.isStorageAvailable()) return;
    try {
      localStorage.setItem('gpk-passkey-id', id);
    } catch {
      // Silently fail
    }
  }

  async getPublicKey(idHash: Hash): Promise<{ x: Hex; y: Hex } | null> {
    if (!this.isStorageAvailable()) return null;
    try {
      const x = localStorage.getItem(`gpk-${idHash}-public-key`);
      const y = localStorage.getItem(`gpk-${idHash}-public-key-y`);
      if (!x || !y) return null;
      return { x: x as Hex, y: y as Hex };
    } catch {
      return null;
    }
  }

  async setPublicKey(idHash: Hash, coords: { x: Hex; y: Hex }): Promise<void> {
    if (!this.isStorageAvailable()) return;
    try {
      localStorage.setItem(`gpk-${idHash}-public-key`, coords.x);
      localStorage.setItem(`gpk-${idHash}-public-key-y`, coords.y);
    } catch {
      // Silently fail
    }
  }

  async clear(): Promise<void> {
    if (!this.isStorageAvailable()) return;
    try {
      // Clear provider data
      localStorage.removeItem('giano_credential_id');
      localStorage.removeItem('giano_account_address');

      // Clear passkey data (note: this doesn't clear all public keys, just the main passkey ID)
      localStorage.removeItem('gpk-passkey-id');

      // TODO: Consider clearing all gpk-* keys if needed
    } catch {
      // Silently fail
    }
  }
}

/**
 * In-memory storage implementation
 */
export class InMemoryStorage implements GianoStorage {
  private credentialId: string | null = null;
  private accountAddress: string | null = null;
  private passkeyId: string | null = null;
  private publicKeys: Map<Hash, { x: Hex; y: Hex }> = new Map();

  isAvailable(): boolean {
    return true;
  }

  // Provider session management
  async getCredentialId(): Promise<string | null> {
    return this.credentialId;
  }

  async setCredentialId(id: string): Promise<void> {
    this.credentialId = id;
  }

  async getAccountAddress(): Promise<string | null> {
    return this.accountAddress;
  }

  async setAccountAddress(address: string): Promise<void> {
    this.accountAddress = address;
  }

  // Passkey management
  async getPasskeyId(): Promise<string | null> {
    return this.passkeyId;
  }

  async setPasskeyId(id: string): Promise<void> {
    this.passkeyId = id;
  }

  async getPublicKey(idHash: Hash): Promise<{ x: Hex; y: Hex } | null> {
    return this.publicKeys.get(idHash) || null;
  }

  async setPublicKey(idHash: Hash, coords: { x: Hex; y: Hex }): Promise<void> {
    this.publicKeys.set(idHash, coords);
  }

  async clear(): Promise<void> {
    this.credentialId = null;
    this.accountAddress = null;
    this.passkeyId = null;
    this.publicKeys.clear();
  }
}

/**
 * Factory function to create storage with automatic fallback
 */
export function createGianoStorage(customStorage?: GianoStorage): GianoStorage {
  if (customStorage) {
    return customStorage;
  }

  const localStorage = new LocalStorage();
  if (localStorage.isAvailable()) {
    return localStorage;
  }

  console.warn(
    'localStorage not available for Giano storage, falling back to memory storage. ' +
    'Data will not persist across page reloads.'
  );
  return new InMemoryStorage();
}