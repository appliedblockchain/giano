import { encodeChallenge } from '@appliedblockchain/giano-common';
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
export function createSignature(keyPair: KeyPair, message: string | Uint8Array): string {
  // Convert message to Uint8Array if it's a string
  const messageBytes = typeof message === 'string' ? ethers.toUtf8Bytes(message) : message;

  // Get the private key from the keypair
  const privateKey = keyPair.keyPair.privateKey;

  // Sign the challenge
  const webAuthnResponse = signWebAuthnChallenge(privateKey, messageBytes);
  // Encode the signature as expected by the contracts
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [
      'tuple(tuple(bytes32 x, bytes32 y) publicKey, bytes authenticatorData, string clientDataJSON, ' +
        'uint256 challengeLocation, uint256 responseTypeLocation, uint256 r, uint256 s)',
    ],
    [[keyPair.publicKey.x, keyPair.publicKey.y], webAuthnResponse.authenticatorData, webAuthnResponse.clientDataJSON],
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
export function createSignedAdminAction(operation: number, operationData: string, nonce: number, keyPair: crypto.KeyPairKeyObjectResult): SignedAdminAction {
  // Prepare the message to sign: keccak256(operation + operationData + nonce)
  const message = ethers.solidityPackedKeccak256(['uint256', 'bytes', 'uint256'], [operation, operationData, nonce]);

  // update create signature to handle the new requirement of inserting the public key
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
  const encodedCalls = calls.map((call) => ethers.AbiCoder.defaultAbiCoder().encode(['address', 'uint256', 'bytes'], [call.target, call.value, call.data]));

  const message = ethers.solidityPackedKeccak256(['bytes[]'], [encodedCalls]);

  const signature = createSignature(keyPair, ethers.getBytes(message));

  return {
    calls,
    signature,
  };
}
