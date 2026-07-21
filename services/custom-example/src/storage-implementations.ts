import type { Hex } from 'viem';

/**
 * Local storage interface for injection implementations
 */
export type GianoStorage = {
  // Unified credential info retrieval
  getCredentialInfo(): Promise<{
    passkeyId: string | null;
    challenge: Uint8Array;
  }>;
  setPasskeyId(id: string): Promise<void>;
  getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null>;
  setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void>;
  isAvailable(): boolean;
};

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

  // Unified credential info retrieval
  async getCredentialInfo(): Promise<{
    passkeyId: string | null;
    challenge: Uint8Array;
  }> {
    const passkeyId = await this.getPasskeyId();
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    return {
      passkeyId,
      challenge,
    };
  }

  // Private method for internal use
  private async getPasskeyId(): Promise<string | null> {
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
}

/**
 * In-memory storage implementation
 *
 * Data is lost when the page reloads. Useful for testing or temporary sessions.
 */
export class InMemoryStorage implements GianoStorage {
  private passkeyId: string | null = null;
  private publicKeys = new Map<string, { x: Hex; y: Hex }>();

  isAvailable(): boolean {
    return true;
  }

  // Unified credential info retrieval
  async getCredentialInfo(): Promise<{
    passkeyId: string | null;
    challenge: Uint8Array;
  }> {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    return {
      passkeyId: this.passkeyId,
      challenge,
    };
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

  console.warn('localStorage not available for Giano storage, falling back to memory storage. ' + 'Data will not persist across page reloads.');
  return new InMemoryStorage();
}
