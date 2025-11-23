import type { ChainType, GianoProviderInjection } from '@appliedblockchain/giano-connector';
import { type Hex, isHex } from 'viem';
import { createGianoStorage, type GianoStorage, InMemoryStorage } from './storage-implementations';
import { bytesToHex, concatBytes, hexToBytes, padBytes, serializeWithBigInt } from './utils';

export type CreateGianoInjectionOptions = {
  /** Custom storage implementation. If not provided, uses localStorage with fallback to in-memory storage */
  storage?: GianoStorage;
  /** Enable backend submission of user operations. When true, includes submitUserOperation hook */
  enableBackendSubmission?: boolean;
  /** Show credential list instead of using automatic selection from storage */
  showListCredentials?: boolean;
};

/**
 * Create a Giano injection with configurable storage and options
 */
export function createGianoInjection(options: CreateGianoInjectionOptions = {}): GianoProviderInjection & {
  setShowListCredentials: (showListCredentials: boolean) => void;
} {
  const { storage, enableBackendSubmission = false } = options;
  const gianoStorage = createGianoStorage(storage);
  let showListCredentials = options.showListCredentials;

  return {
    setShowListCredentials: (showListCredentialsOption: boolean) => {
      showListCredentials = showListCredentialsOption;
    },

    getNameForCredential: async () => {
      return 'Giano Passkey';
    },

    getCredentialInfo: async () => {
      const { passkeyId, challenge } = await gianoStorage.getCredentialInfo();
      return {
        credentialId: !showListCredentials && passkeyId ? new Uint8Array(Buffer.from(passkeyId, 'base64')) : null,
        challenge,
        showListCredentials,
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
        walletFactoryAddress: `0x${bytesToHex(walletFactoryAddress)}`,
        chainId: parseInt(bytesToHex(chainId), 16),
        chainType: parseInt(bytesToHex(chainType), 16) as ChainType,
      };
    },

    onCredentialSignedIn: async (credential) => {
      console.log('Credential signed in', { credential });
      return true;
    },

    getPublicKeyByCredentialId: async (rawId: ArrayBuffer) => {
      const publicKey = await gianoStorage.getPublicKey(rawId);

      if (!publicKey || !isHex(publicKey.x, { strict: true }) || !isHex(publicKey.y, { strict: true })) {
        throw new Error('Public key not found');
      }
      return publicKey;
    },

    onCredentialKey: async (rawId: ArrayBuffer, xyVector: { x: Hex; y: Hex }) => {
      console.log('onCredentialKey', { rawId: Buffer.from(rawId).toString('hex'), xyVector });
      await gianoStorage.setPublicKey(rawId, xyVector);
    },

    ...(enableBackendSubmission && {
      submitUserOperation: async (signedUserOp) => {
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

          // Return the user operation hash - frontend will handle waiting for receipt
          return result.userOperationHash;
        } catch (error) {
          console.error('UserOp submission failed:', error);
          throw error;
        }
      },
    }),
  };
}

/**
 * Default injection using localStorage with automatic fallback and backend submission enabled
 */
export const gianoInjection = createGianoInjection({ enableBackendSubmission: true });

/**
 * Memory-only injection (no persistence) with backend submission enabled
 */
export const gianoMemoryInjection = createGianoInjection({
  storage: new InMemoryStorage(),
  enableBackendSubmission: true,
});
