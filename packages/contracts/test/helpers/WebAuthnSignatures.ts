import type crypto from 'crypto';
import { ethers } from 'hardhat';
import { createKeypair, signWebAuthnChallenge } from '../utils';

type PublicKey = {
  x: string;
  y: string;
};

type KeyPair = {
  publicKey: PublicKey;
  keyPair: crypto.KeyPairKeyObjectResult;
};

type WebAuthnSignature = {
  publicKey: {
    x: string;
    y: string;
  };
  authenticatorData: Uint8Array;
  clientDataJSON: string;
  challengeLocation: number;
  responseTypeLocation: number;
  r: bigint;
  s: bigint;
};

type Call = {
  target: string;
  value: number | bigint;
  data: string;
};

type SignedCall = {
  call: Call;
  signature: string;
};

type SignedAdminAction = {
  operation: number;
  operationData: string;
  nonce: number;
  signature: string;
};

type BatchCall = {
  calls: Call[];
  signature: string;
};

/**
 * Generate a testing keypair for WebAuthn signatures
 * @returns The keypair with formatted public key for Solidity
 */
export function generateTestKeypair(): KeyPair {
  const { x, y, keyPair } = createKeypair();

  // Format the public key for Solidity contracts
  const publicKey = {
    x: ethers.hexlify(x),
    y: ethers.hexlify(y),
  };

  return { publicKey, keyPair };
}

/**
 * Create a real WebAuthn signature for testing
 * @param keyPair Cryptographic keypair
 * @param message Message to sign
 * @returns Encoded signature for use with Account contract
 */
export function createSignature(keyPair: crypto.KeyPairKeyObjectResult, message: string | Uint8Array): string {
  // Convert message to Uint8Array if it's a string
  const messageBytes = typeof message === 'string' ? ethers.toUtf8Bytes(message) : message;

  // Get the private key from the keypair
  const privateKey = keyPair.privateKey;

  // Sign the challenge
  const webAuthnResponse = signWebAuthnChallenge(privateKey, messageBytes);

  // Get the public key
  const publicKeyBuffer = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const x = publicKeyBuffer.subarray(27, 59);
  const y = publicKeyBuffer.subarray(59, 91);

  // Find challenge and response type locations in clientDataJSON
  const clientDataJSON = webAuthnResponse.clientDataJSON.toString();
  const challengeLocation = clientDataJSON.indexOf('"challenge"');
  const responseTypeLocation = clientDataJSON.indexOf('"type"');

  // Get the signature components r and s
  // Simple ASN.1 parsing (in a real implementation, use a proper ASN.1 parser)
  const signature = webAuthnResponse.signature;
  const rLength = signature[3];
  const rStart = 4;
  const sStart = rStart + rLength + 2;
  const sLength = signature[rStart + rLength + 1];

  const r = ethers.toBigInt(signature.slice(rStart, rStart + rLength));
  const s = ethers.toBigInt(signature.slice(sStart, sStart + sLength));

  const signatureObj: WebAuthnSignature = {
    publicKey: {
      x: ethers.zeroPadValue(ethers.hexlify(x), 32),
      y: ethers.zeroPadValue(ethers.hexlify(y), 32),
    },
    authenticatorData: webAuthnResponse.authenticatorData,
    clientDataJSON,
    challengeLocation,
    responseTypeLocation,
    r,
    s,
  };

  // Encode the signature as expected by the contracts
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [
      'tuple(tuple(bytes32 x, bytes32 y) publicKey, bytes authenticatorData, string clientDataJSON, ' +
        'uint256 challengeLocation, uint256 responseTypeLocation, uint256 r, uint256 s)',
    ],
    [signatureObj],
  );
}

/**
 * Create a signed admin action for testing
 * @param operation Operation code
 * @param operationData Encoded operation data
 * @param nonce Action nonce
 * @param keyPair Keypair for signing
 * @returns The signed admin action
 */
export function createSignedAdminAction(
  operation: number,
  operationData: string,
  nonce: number,
  keyPair: crypto.KeyPairKeyObjectResult,
): SignedAdminAction {
  // Prepare the message to sign: keccak256(operation + operationData + nonce)
  const message = ethers.solidityPackedKeccak256(['uint256', 'bytes', 'uint256'], [operation, operationData, nonce]);

  const signature = createSignature(keyPair, ethers.getBytes(message));

  return {
    operation,
    operationData,
    nonce,
    signature,
  };
}

/**
 * Sign a call object for execution
 * @param call Call object with target, value and data
 * @param keyPair Keypair for signing
 * @returns The signed call
 */
export function createSignedCall(call: Call, keyPair: crypto.KeyPairKeyObjectResult): SignedCall {
  // Prepare the message to sign: keccak256(target + value + data)
  const message = ethers.solidityPackedKeccak256(['address', 'uint256', 'bytes'], [call.target, call.value, call.data]);

  const signature = createSignature(keyPair, ethers.getBytes(message));

  return {
    call,
    signature,
  };
}

/**
 * Sign a batch of call objects for execution
 * @param calls Array of call objects
 * @param keyPair Keypair for signing
 * @returns The signed batch call
 */
export function createBatchCall(calls: Call[], keyPair: crypto.KeyPairKeyObjectResult): BatchCall {
  // Prepare the message containing all calls
  const encodedCalls = calls.map((call) =>
    ethers.AbiCoder.defaultAbiCoder().encode(['address', 'uint256', 'bytes'], [call.target, call.value, call.data]),
  );

  const message = ethers.solidityPackedKeccak256(['bytes[]'], [encodedCalls]);

  const signature = createSignature(keyPair, ethers.getBytes(message));

  return {
    calls,
    signature,
  };
}
