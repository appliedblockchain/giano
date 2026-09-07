import type { Hex } from 'viem';

/** base64url without padding, as WebAuthn JSON encodes binary fields. */
export function toBase64Url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = typeof btoa === 'function' ? btoa(binary) : Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = typeof atob === 'function' ? atob(padded) : Buffer.from(padded, 'base64').toString('binary');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Serializes a registration PublicKeyCredential into WebAuthn JSON for the API. */
export function serializeRegistrationCredential(credential: Omit<PublicKeyCredential, 'toJSON'>) {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: 'public-key' as const,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      transports: typeof response.getTransports === 'function' ? response.getTransports() : undefined,
    },
    clientExtensionResults:
      typeof credential.getClientExtensionResults === 'function' ? credential.getClientExtensionResults() : {},
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
  };
}

/** Serializes an authentication PublicKeyCredential into WebAuthn JSON for the API. */
export function serializeAuthenticationCredential(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: 'public-key' as const,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
    },
    clientExtensionResults:
      typeof credential.getClientExtensionResults === 'function' ? credential.getClientExtensionResults() : {},
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
  };
}

const toHexQuantity = (value: bigint | number | string | undefined): Hex | undefined =>
  value === undefined ? undefined : (`0x${BigInt(value).toString(16)}` as Hex);

/**
 * Converts a signed viem user operation (bigint fields) into the JSON-RPC hex encoding
 * the wallet-api accepts. Non-userop fields (like the legacy `account` envelope the
 * provider attaches) are dropped — the server never trusts request-side EntryPoints.
 */
export function serializeUserOperation(signedUserOp: Record<string, unknown>) {
  const op = signedUserOp as {
    sender: string;
    nonce: bigint | string;
    callData: Hex;
    callGasLimit: bigint | string;
    verificationGasLimit: bigint | string;
    preVerificationGas: bigint | string;
    maxFeePerGas: bigint | string;
    maxPriorityFeePerGas: bigint | string;
    signature: Hex;
    factory?: string;
    factoryData?: Hex;
    paymaster?: string;
    paymasterVerificationGasLimit?: bigint | string;
    paymasterPostOpGasLimit?: bigint | string;
    paymasterData?: Hex;
  };
  return {
    sender: op.sender,
    nonce: toHexQuantity(op.nonce as bigint),
    callData: op.callData,
    callGasLimit: toHexQuantity(op.callGasLimit as bigint),
    verificationGasLimit: toHexQuantity(op.verificationGasLimit as bigint),
    preVerificationGas: toHexQuantity(op.preVerificationGas as bigint),
    maxFeePerGas: toHexQuantity(op.maxFeePerGas as bigint),
    maxPriorityFeePerGas: toHexQuantity(op.maxPriorityFeePerGas as bigint),
    signature: op.signature,
    ...(op.factory ? { factory: op.factory, factoryData: op.factoryData } : {}),
    ...(op.paymaster
      ? {
          paymaster: op.paymaster,
          paymasterData: op.paymasterData,
          paymasterVerificationGasLimit: toHexQuantity(op.paymasterVerificationGasLimit),
          paymasterPostOpGasLimit: toHexQuantity(op.paymasterPostOpGasLimit),
        }
      : {}),
  };
}
