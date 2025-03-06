import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';
import type { Account, AccountFactory, AccountRegistry } from '../typechain-types';
import { deployContracts } from './helpers/testSetup';

// Define PublicKey type consistent with the WebAuthnSignatures file
type PublicKey = {
  x: string;
  y: string;
};

// Helper function to create and get an account instance
async function createAndGetAccount(
  accountFactory: AccountFactory,
  adminKeypair: { publicKey: PublicKey },
  accountRegistry: AccountRegistry,
): Promise<Account> {
  // Create a new account with the admin keypair
  const registryAddress = await accountRegistry.getAddress();
  const tx = await accountFactory.deployAccount(adminKeypair.publicKey, registryAddress);
  const receipt = await tx.wait();

  // Get the account address from the event logs
  const deployedEvents = receipt?.logs
    .map((log) => {
      try {
        return accountFactory.interface.parseLog({ topics: log.topics, data: log.data });
      } catch (e) {
        return null;
      }
    })
    .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'AccountDeployed');

  if (!deployedEvents?.length || !deployedEvents[0].args) {
    throw new Error('AccountDeployed event not found');
  }

  const accountAddress = deployedEvents[0].args.account;
  return await ethers.getContractAt('Account', accountAddress);
}

describe('Account Contract', function () {
  beforeEach(async () => {
    await loadFixture(deployContracts);
  });

  describe('Initialization', function () {
    it('should initialize with correct registry address', async function () {
      // Deploy a new account using the factory from the fixture
      const { accountFactory, accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(accountFactory, adminKeypair, accountRegistry);

      // Verify the registry is set correctly
      expect(await account.registry()).to.equal(await accountRegistry.getAddress());
    });

    it('should set up the initial admin key correctly', async function () {
      const { accountFactory, accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(accountFactory, adminKeypair, accountRegistry);

      // Check the key exists and has admin role (role=2)
      const keyInfo = await account.getKeyInfo(adminKeypair.publicKey);
      expect(keyInfo.publicKey.x).to.equal(adminKeypair.publicKey.x);
      expect(keyInfo.publicKey.y).to.equal(adminKeypair.publicKey.y);
      expect(keyInfo.role).to.equal(2); // Role.ADMIN = 2
    });

    it('should start with admin key count of 1', async function () {
      const { accountFactory, accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(accountFactory, adminKeypair, accountRegistry);

      expect(await account.getAdminKeyCount()).to.equal(1);
    });

    it('should start with nonces at 0', async function () {
      const { accountFactory, accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(accountFactory, adminKeypair, accountRegistry);

      expect(await account.getNonce()).to.equal(0); // Transaction nonce
      expect(await account.getAdminNonce()).to.equal(0); // Admin nonce
    });

    it('should not be paused initially', async function () {
      const { accountFactory, accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(accountFactory, adminKeypair, accountRegistry);

      const [isPaused, pausedUntil] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntil).to.equal(0);
    });
  });

  describe('Key Management', function () {
    describe('Key Requests', function () {
      it('should allow registry to request adding a key');
      it('should emit KeyRequested event with correct parameters');
      it('should reject requests for keys that already exist');
      it('should only allow registry to request keys');
      it('should generate unique request IDs');
    });

    describe('Key Request Approval', function () {
      it('should add a key when request is approved by admin');
      it('should increment admin key count when adding admin key');
      it('should emit KeyRequestApproved and KeyAdded events');
      it('should remove the key request after approval');
      it('should notify registry about the added key');
      it('should only allow approved requests with valid signatures');
      it('should validate operation data matches request ID');
    });

    describe('Key Request Rejection', function () {
      it('should reject a key request when called by admin');
      it('should emit KeyRequestRejected event');
      it('should remove the key request after rejection');
      it('should fail when request does not exist');
      it('should only allow rejection with valid admin signature');
    });

    describe('Key Removal', function () {
      it('should remove an existing key');
      it('should fail to remove a non-existent key');
      it('should decrement admin key count when removing admin key');
      it('should prevent removing the last admin key');
      it('should emit KeyRemoved event');
      it('should notify registry about the removed key');
      it('should only allow removal with valid admin signature');
    });

    describe('Key Role Changes', function () {
      it('should change role of an existing key');
      it('should fail to change role of a non-existent key');
      it('should increment admin key count when upgrading to admin');
      it('should decrement admin key count when downgrading from admin');
      it('should prevent downgrading the last admin key');
      it('should emit KeyRoleChanged event');
      it('should validate operation data matches key and new role');
    });
  });

  describe('Transaction Execution', function () {
    describe('Single Transactions', function () {
      it('should execute a transaction with valid signature');
      it('should reject execution with invalid signature');
      it('should increment nonce after successful execution');
      it('should emit Executed event');
      it('should pass correct value to target contract');
      it('should forward revert reasons from target contracts');
      it('should prevent execution when paused');
      it('should respect rate limits');
    });

    describe('Batch Transactions', function () {
      it('should execute multiple transactions in one call');
      it('should validate batch challenge correctly');
      it('should reject with invalid signature');
      it('should increment nonce only once for the batch');
      it('should emit one Executed event for the batch');
      it('should revert entire batch if one call fails');
      it('should prevent execution when paused');
      it('should respect rate limits');
    });
  });

  describe('Admin Operations', function () {
    it('should validate admin signatures correctly');
    it('should increment admin nonce after operations');
    it('should emit AdminActionExecuted event');
    it('should reject operations with invalid nonce');
    it('should reject operations with wrong operation type');
    it('should reject operations with invalid signature');
  });

  describe('Pause Functionality', function () {
    it('should allow admin to pause the account');
    it('should emit AccountPaused event with correct timestamp');
    it('should prevent transaction execution while paused');
    it('should handle indefinite pausing');
    it('should allow admin to unpause the account');
    it('should emit AccountUnpaused event');
    it('should allow transaction execution after unpausing');
    it('should report pause status correctly');
  });

  describe('Rate Limiting', function () {
    it('should track operation count correctly');
    it('should reset counter after the rate limit period');
    it('should reject operations exceeding rate limit');
    it('should report rate limit status correctly');
  });

  describe('ERC Support', function () {
    describe('ERC1271 Implementation', function () {
      it('should validate signatures according to ERC1271');
      it('should return magic value for valid signatures');
      it('should return failure value for invalid signatures');
    });

    describe('ERC721/ERC1155 Receiver', function () {
      it('should implement onERC721Received correctly');
      it('should implement onERC1155Received correctly');
      it('should implement onERC1155BatchReceived correctly');
      it('should support relevant interfaces');
    });
  });

  describe('Utility Functions', function () {
    it('should calculate challenge hash correctly for single calls');
    it('should calculate challenge hash correctly for batch calls');
    it('should calculate admin challenge hash correctly');
    it('should calculate key hash correctly');
  });

  describe('Security Features', function () {
    it('should prevent reentrancy attacks');
    it('should prevent unauthorized admin operations');
    it('should handle key rotation securely');
    it('should validate signatures correctly under different scenarios');
  });
});
