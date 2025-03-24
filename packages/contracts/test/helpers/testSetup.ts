import { ethers } from 'hardhat';
import hre from 'hardhat';
import ignitionModules from '../../ignition/modules';
import type { AccountFactory, AccountRegistry, TestContract } from '../../typechain-types';
import { createKeypair } from '../utils';
import crypto from 'node:crypto';
import { BytesLike } from 'ethers';

export type HexifiedPublicKey = {
  x: string;
  y: string;
};

export type PublicKeyCredential = {
  publicKey: HexifiedPublicKey;
  keyPair: crypto.KeyPairKeyObjectResult;
  credentialId: BytesLike;
};

/**
 * Generate a testing keypair for WebAuthn signatures
 * @returns The keypair with formatted public key for Solidity
 */
export function generateTestKeypair(): PublicKeyCredential {
  const { x, y, keyPair } = createKeypair();

  // Format the public key for Solidity contracts
  const publicKey = {
    x: ethers.hexlify(x),
    y: ethers.hexlify(y),
  };

  // Generate a random credential ID
  const credentialId = ethers.randomBytes(32);

  return { publicKey, keyPair, credentialId };
}

/**
 * Deploy contracts fixture
 * @return Object with all deployed contracts and test keypairs
 */
async function deployContracts() {
  const [owner, user1, user2] = await ethers.getSigners();

  const adminKeyPair = generateTestKeypair();
  const executorKeypair = generateTestKeypair();
  const userKeypair = generateTestKeypair();

  const result = await hre.ignition.deploy(ignitionModules);
  const accountRegistry = result.accountRegistry as unknown as AccountRegistry;
  const accountFactory = result.accountFactory as unknown as AccountFactory;
  const testContract = result.testContract as unknown as TestContract;

  return {
    accountRegistry,
    accountFactory,
    testContract,
    owner,
    user1,
    user2,
    adminKeyPair,
    executorKeypair,
    userKeypair,
  };
}

export { deployContracts };
