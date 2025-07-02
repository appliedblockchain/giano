import type { Hex } from 'viem';
import type { GianoStorage } from '@appliedblockchain/giano-connector';

/**
 * localStorage-based implementation
 *
 * Uses browser localStorage with specific key prefixes.
 * Projects may want to customize these keys or implement different storage strategies.
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

  async getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null> {
    if (!this.isStorageAvailable()) return null;
    try {
      const x = localStorage.getItem(`gpk-${Buffer.from(rawId).toString('hex')}-public-key`);
      const y = localStorage.getItem(`gpk-${Buffer.from(rawId).toString('hex')}-public-key-y`);
      if (!x || !y) return null;
      return { x: x as Hex, y: y as Hex };
    } catch {
      return null;
    }
  }

  async setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void> {
    if (!this.isStorageAvailable()) return;
    try {
      localStorage.setItem(`gpk-${Buffer.from(rawId).toString('hex')}-public-key`, coords.x);
      localStorage.setItem(`gpk-${Buffer.from(rawId).toString('hex')}-public-key-y`, coords.y);
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
 *
 * Data is lost when the page reloads. Useful for testing or temporary sessions.
 */
export class InMemoryStorage implements GianoStorage {
  private credentialId: string | null = null;
  private accountAddress: string | null = null;
  private passkeyId: string | null = null;
  private publicKeys = new Map<string, { x: Hex; y: Hex }>();

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

  async getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null> {
    return this.publicKeys.get(Buffer.from(rawId).toString('hex')) || null;
  }

  async setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void> {
    this.publicKeys.set(Buffer.from(rawId).toString('hex'), coords);
  }

  async clear(): Promise<void> {
    this.credentialId = null;
    this.accountAddress = null;
    this.passkeyId = null;
    this.publicKeys.clear();
  }
}

/**
 * DEMO: Server-side storage implementation example
 *
 * ⚠️ This is for demonstration purposes only!
 * In production, you'd implement:
 * - Proper authentication and authorization
 * - Secure database storage instead of simple REST API
 * - Data encryption and validation
 * - Rate limiting and security measures
 * - Error handling and retry logic
 * - Backup and recovery mechanisms
 */
export class ServerStorage implements GianoStorage {
  constructor(
    private apiEndpoint: string,
    private userId: string,
    private authToken?: string
  ) {}

  private async request(path: string, options: RequestInit = {}): Promise<any> {
    const headers = {
      'Content-Type': 'application/json',
      ...(this.authToken && { Authorization: `Bearer ${this.authToken}` }),
      ...options.headers,
    };

    const response = await fetch(`${this.apiEndpoint}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      throw new Error(`Storage request failed: ${response.statusText}`);
    }

    return response.json();
  }

  isAvailable(): boolean {
    return navigator.onLine;
  }

  // Provider session management
  async getCredentialId(): Promise<string | null> {
    try {
      const data = await this.request(`/users/${this.userId}/session`);
      return data.credentialId || null;
    } catch {
      return null;
    }
  }

  async setCredentialId(id: string): Promise<void> {
    try {
      await this.request(`/users/${this.userId}/session`, {
        method: 'PUT',
        body: JSON.stringify({ credentialId: id }),
      });
    } catch {
      // Handle error appropriately
    }
  }

  async getAccountAddress(): Promise<string | null> {
    try {
      const data = await this.request(`/users/${this.userId}/session`);
      return data.accountAddress || null;
    } catch {
      return null;
    }
  }

  async setAccountAddress(address: string): Promise<void> {
    try {
      await this.request(`/users/${this.userId}/session`, {
        method: 'PUT',
        body: JSON.stringify({ accountAddress: address }),
      });
    } catch {
      // Handle error appropriately
    }
  }

  // Passkey management
  async getPasskeyId(): Promise<string | null> {
    try {
      const data = await this.request(`/users/${this.userId}/passkeys`);
      return data.passkeyId || null;
    } catch {
      return null;
    }
  }

  async setPasskeyId(id: string): Promise<void> {
    try {
      await this.request(`/users/${this.userId}/passkeys`, {
        method: 'PUT',
        body: JSON.stringify({ passkeyId: id }),
      });
    } catch {
      // Handle error appropriately
    }
  }

  async getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null> {
    try {
      const data = await this.request(`/users/${this.userId}/public-keys/${Buffer.from(rawId).toString('hex')}`);
      return data.publicKey || null;
    } catch {
      return null;
    }
  }

  async setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void> {
    try {
      await this.request(`/users/${this.userId}/public-keys/${Buffer.from(rawId).toString('hex')}`, {
        method: 'PUT',
        body: JSON.stringify({ publicKey: coords }),
      });
    } catch {
      // Handle error appropriately
    }
  }

  async clear(): Promise<void> {
    try {
      await this.request(`/users/${this.userId}/session`, { method: 'DELETE' });
      await this.request(`/users/${this.userId}/passkeys`, { method: 'DELETE' });
    } catch {
      // Handle error appropriately
    }
  }
}

/**
 * Factory function to create storage with automatic fallback
 *
 * This is an example implementation. Projects may want to implement
 * their own factory logic based on their specific requirements.
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