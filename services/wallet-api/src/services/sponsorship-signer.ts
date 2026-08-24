import type { Address, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

/**
 * The sponsorship signer.
 *
 * Behind a narrow interface on purpose: the key that authorises spending against customer funds
 * is the highest-value secret in the system, and where it lives is a security decision that must
 * be changeable without touching the API or the ledger.
 *
 * Two implementations. Production signs with a key held in an AWS HSM, driven through Applied
 * Blockchain's `evm-hsm-signer` behind `HsmSignerAdapter`, so the key never enters this process.
 * Local development, tests, the e2e stack and testnet sign with a key in an environment variable,
 * which `loadConfig` refuses for a production deployment.
 *
 * The signed payload deliberately excludes the account signature — the user's passkey signs the
 * whole operation afterwards, *including* this authorisation, so neither signature can be altered
 * without invalidating the other.
 */

export type AuthorisationPayload = {
  chainId: number;
  paymaster: Address;
  sender: Address;
  nonce: bigint;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  /** The 16-byte tenant id. Signed, which is what stops a user redirecting the charge. */
  tenantId: Hex;
  validUntil: number;
  validAfter: number;
  /** Pinned here, so a later rate change cannot alter what this authorisation charges. */
  feeWei: bigint;
};

export type SponsorshipSigner = {
  /** Logged and used as a metric label, so a signature from an unexpected key is visible. */
  readonly keyId: string;
  address: () => Promise<Address>;
  signAuthorisation: (payload: AuthorisationPayload) => Promise<Hex>;
  health: () => Promise<'ok' | 'unavailable'>;
};

/** Matches `GianoPaymaster.SPONSORSHIP_AUTHORISATION_TYPEHASH`. */
export const AUTHORISATION_TYPES = {
  SponsorshipAuthorisation: [
    { name: 'sender', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'callDataHash', type: 'bytes32' },
    { name: 'accountGasLimits', type: 'bytes32' },
    { name: 'preVerificationGas', type: 'uint256' },
    { name: 'gasFees', type: 'bytes32' },
    { name: 'paymasterVerificationGasLimit', type: 'uint256' },
    { name: 'paymasterPostOpGasLimit', type: 'uint256' },
    { name: 'tenantId', type: 'bytes16' },
    { name: 'validUntil', type: 'uint48' },
    { name: 'validAfter', type: 'uint48' },
    { name: 'feeWei', type: 'uint128' },
  ],
} as const;

/**
 * The EIP-712 domain the contract builds. `verifyingContract` and `chainId` are what give replay
 * separation across paymaster addresses and chains for free.
 */
export function authorisationDomain(chainId: number, paymaster: Address) {
  return { name: 'GianoPaymaster', version: '1', chainId, verifyingContract: paymaster } as const;
}

export function toTypedDataMessage(payload: AuthorisationPayload, callDataHash: Hex) {
  return {
    sender: payload.sender,
    nonce: payload.nonce,
    callDataHash,
    accountGasLimits: payload.accountGasLimits,
    preVerificationGas: payload.preVerificationGas,
    gasFees: payload.gasFees,
    paymasterVerificationGasLimit: payload.paymasterVerificationGasLimit,
    paymasterPostOpGasLimit: payload.paymasterPostOpGasLimit,
    tenantId: payload.tenantId,
    validUntil: payload.validUntil,
    validAfter: payload.validAfter,
    feeWei: payload.feeWei,
  };
}

/**
 * A signer holding the key in process.
 *
 * For development, tests, the e2e stack and testnet — `loadConfig` refuses it when
 * `GIANO_DEPLOYMENT_CLASS=production`, because a key in an environment variable has the worst
 * blast radius of any option and this one authorises spending customer funds. The gate is the
 * deployment's class rather than `NODE_ENV` because a testnet deployment runs as a production
 * build, and testnet is a place this signer belongs.
 */
export function createLocalSponsorshipSigner(privateKey: Hex, keyId = 'local'): SponsorshipSigner {
  const account = privateKeyToAccount(privateKey);
  return {
    keyId,
    address: async () => account.address,
    async signAuthorisation(payload) {
      const { keccak256 } = await import('viem');
      return account.signTypedData({
        domain: authorisationDomain(payload.chainId, payload.paymaster),
        types: AUTHORISATION_TYPES,
        primaryType: 'SponsorshipAuthorisation',
        message: toTypedDataMessage(payload, keccak256(payload.callData)),
      });
    },
    health: async () => 'ok',
  };
}

/**
 * A signer backed by a hardware-held key.
 *
 * Production uses an AWS HSM key through `evm-hsm-signer`, which is an implementation of the
 * adapter below rather than anything this module needs to know about. The signing call is
 * deliberately left to the deployment's SDK rather than pinned to one vendor here: what this
 * codebase guarantees is that the key material never enters this process, and that is a property
 * of the interface, not of the vendor.
 *
 * `signDigest` is the whole boundary — this module builds the EIP-712 digest itself and asks only
 * for a signature over it, which is the shape every remote key service offers.
 */
export type HsmSignerAdapter = {
  keyId: string;
  /** Returns the secp256k1 address the key recovers to; must be in the contract's signer set. */
  getAddress: () => Promise<Address>;
  /** Signs a 32-byte digest, returning a 65-byte (r, s, v) signature. */
  signDigest: (digest: Hex) => Promise<Hex>;
  ping?: () => Promise<void>;
};

export function createHsmSponsorshipSigner(adapter: HsmSignerAdapter): SponsorshipSigner {
  return {
    keyId: adapter.keyId,
    address: () => adapter.getAddress(),
    async signAuthorisation(payload) {
      const { hashTypedData, keccak256 } = await import('viem');
      const digest = hashTypedData({
        domain: authorisationDomain(payload.chainId, payload.paymaster),
        types: AUTHORISATION_TYPES,
        primaryType: 'SponsorshipAuthorisation',
        message: toTypedDataMessage(payload, keccak256(payload.callData)),
      });
      return adapter.signDigest(digest);
    },
    async health() {
      try {
        if (adapter.ping) await adapter.ping();
        else await adapter.getAddress();
        return 'ok';
      } catch {
        // The caller turns this into `temporarily-unavailable` rather than a rule refusal: an
        // outage and a misconfiguration call for completely different responses.
        return 'unavailable';
      }
    },
  };
}
