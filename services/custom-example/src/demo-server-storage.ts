import type { Hash, Hex } from 'viem';
import type { GianoStorage } from '@appliedblockchain/giano-connector';

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