import type { Hash, Hex } from 'viem';
import type { GianoProviderInjection, ChainType } from '@appliedblockchain/giano-connector';
import type { GianoStorage } from '@appliedblockchain/giano-connector';
import { createGianoStorage, InMemoryStorage } from '@appliedblockchain/giano-connector';

// Helper functions (same as in giano-local-storage-injection.ts)
function hexToBytes(hex: string) {
  hex = hex.replace(/^0x/g, '');
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function concatBytes(bytes: Uint8Array[]) {
  const totalLength = bytes.reduce((acc, curr) => acc + curr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const byte of bytes) {
    result.set(byte, offset);
    offset += byte.length;
  }
  return result;
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function padBytes(bytes: Uint8Array, size: number) {
  if (bytes.length < size) {
    return concatBytes([new Uint8Array(size - bytes.length).fill(0), bytes]);
  }
  return bytes;
}

/**
 * Helper function to serialize with BigInt support
 */
function serializeWithBigInt(obj: any): string {
  return JSON.stringify(obj, (key, value) =>
    typeof value === 'bigint' ? value.toString() : value
  );
}

/**
 * Create a Giano injection with configurable storage
 */
export function createGianoInjection(storage?: GianoStorage): GianoProviderInjection {
  const gianoStorage = createGianoStorage(storage);

  return {
    getNameForCredential: async () => {
      return 'Giano Passkey';
    },

    getCredentialInfo: async () => {
      const passkeyIdBase64 = await gianoStorage.getPasskeyId();
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      return {
        credentialId: passkeyIdBase64 ? new Uint8Array(Buffer.from(passkeyIdBase64, 'base64')) : null,
        challenge,
      };
    },

    onCredentialCreated: async (credentialName, challenge, credential) => {
      const passkeyIdBase64 = Buffer.from(credential.rawId).toString('base64');
      await gianoStorage.setPasskeyId(passkeyIdBase64);
      return null; // proceed to create a smart wallet
    },

    encodeUserId: (id: string, gianoSmartWalletFactoryAddress: string, chainId: string, chainType: ChainType) => {
      return concatBytes([
        padBytes(hexToBytes(id), 16),
        padBytes(hexToBytes(gianoSmartWalletFactoryAddress), 20),
        padBytes(hexToBytes(chainId), 4),
        padBytes(hexToBytes(chainType.toString(16)), 1),
      ]);
    },

    decodeUserId: (userId: Uint8Array) => {
      const userIdSlice = userId.slice(0, 16);
      const walletFactoryAddress = userId.slice(16, 36);
      const chainId = userId.slice(36, 40);
      const chainType = userId.slice(40, 41);

      return {
        userId: [
          bytesToHex(userIdSlice.slice(0, 4)),
          bytesToHex(userIdSlice.slice(4, 6)),
          bytesToHex(userIdSlice.slice(6, 8)),
          bytesToHex(userIdSlice.slice(8, 10)),
          bytesToHex(userIdSlice.slice(10)),
        ].join('-'),
        walletFactoryAddress: '0x' + bytesToHex(walletFactoryAddress),
        chainId: parseInt(bytesToHex(chainId), 16),
        chainType: parseInt(bytesToHex(chainType), 16) as ChainType,
      };
    },

    onCredentialSignedIn: async (credential) => {
      console.log('Credential signed in', { credential });
      return true;
    },

    getPublicKeyByCredentialId: async (idHash: Hash) => {
      const publicKey = await gianoStorage.getPublicKey(idHash);
      if (!publicKey) {
        throw new Error('Public key not found');
      }
      return publicKey;
    },

    onCredentialKey: async (idHash: Hash, xyVector: { x: Hex; y: Hex }) => {
      console.log('onCredentialKey', { idHash, xyVector });
      await gianoStorage.setPublicKey(idHash, xyVector);
    },

    onUserOperationSigned: async (signedUserOp) => {
      try {
        // Submit to backend for validation and bundler submission
        const response = await fetch('/api/submit-userop', {
          method: 'POST',
          body: serializeWithBigInt(signedUserOp),
          headers: { 'Content-Type': 'application/json' },
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(`Backend submission failed: ${errorData.error}`);
        }

        const result = await response.json();
        console.log('Backend submission successful:', result);

        // Return the transaction receipt from backend
        return result.receipt;
      } catch (error) {
        console.error('UserOp submission failed:', error);
        throw error;
      }
    },
  };
}

/**
 * Default injection using localStorage with automatic fallback
 */
export const gianoInjection = createGianoInjection();

/**
 * Memory-only injection (no persistence)
 */
export const gianoMemoryInjection = createGianoInjection(new InMemoryStorage());
