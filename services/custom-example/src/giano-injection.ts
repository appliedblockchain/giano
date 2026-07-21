import type { ChainType, GianoProviderInjection } from '@appliedblockchain/giano-connector/embedded';
import { type Hex, isHex } from 'viem';
import { createGianoStorage, type GianoStorage, InMemoryStorage } from './storage-implementations';
import { bytesToHex, concatBytes, hexToBytes, padBytes } from './utils';

export type CreateGianoInjectionOptions = {
  /** Custom storage implementation. If not provided, uses localStorage with fallback to in-memory storage */
  storage?: GianoStorage;
  /** Show credential list instead of using automatic selection from storage */
  showListCredentials?: boolean;
};

/**
 * Create a Giano injection with configurable storage and options
 */
export function createGianoInjection(options: CreateGianoInjectionOptions = {}): GianoProviderInjection & {
  setShowListCredentials: (showListCredentials: boolean) => void;
} {
  const { storage } = options;
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

  };
}

/**
 * Default no-backend injection: localStorage with automatic fallback, user operations
 * go straight to the bundler. For server-side storage/verification/relay use
 * `createWalletApiInjection` from @appliedblockchain/giano-connector instead.
 */
export const gianoInjection = createGianoInjection();

/**
 * Memory-only injection (no persistence)
 */
export const gianoMemoryInjection = createGianoInjection({
  storage: new InMemoryStorage(),
});
