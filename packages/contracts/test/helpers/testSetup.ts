import { ethers } from 'hardhat';
import hre from 'hardhat';
import ignitionModules from '../../ignition/modules';
import type { AccountFactory, AccountRegistry, TestContract } from '../../typechain-types';
import { generateTestKeypair } from './WebAuthnSignatures';

/**
 * Deploy contracts fixture
 * @return Object with all deployed contracts and test keypairs
 */
async function deployContracts() {
  const [owner, user1, user2] = await ethers.getSigners();

  const adminKeypair = generateTestKeypair();
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
    adminKeypair,
    executorKeypair,
    userKeypair,
  };
}

export { deployContracts };
