import { ethers } from 'hardhat';
import type { AccountFactory, AccountRegistry } from '../typechain-types';
import { generateTestKeypair } from './helpers/testSetup';

describe('AccountRegistry Contract', function () {
  // Account Role enum for testing
  const Role = {
    NONE: 0,
    EXECUTOR: 1,
    ADMIN: 2,
  };

  async function deployAccountRegistryFixture() {
    const [owner, user1, user2] = await ethers.getSigners();

    // Generate real keypairs for testing
    const adminKeypair = generateTestKeypair();
    const executorKeypair = generateTestKeypair();
    const additionalKeypair = generateTestKeypair();

    // Deploy factory
    const AccountFactoryFactory = await ethers.getContractFactory('AccountFactory');
    const accountFactory = (await AccountFactoryFactory.deploy()) as AccountFactory;

    // Deploy registry
    const AccountRegistryFactory = await ethers.getContractFactory('AccountRegistry');
    const accountRegistry = (await AccountRegistryFactory.deploy(await accountFactory.getAddress())) as AccountRegistry;

    return {
      accountFactory,
      accountRegistry,
      owner,
      user1,
      user2,
      adminKeypair,
      executorKeypair,
      additionalKeypair,
    };
  }

  describe('Construction', function () {
    it('should initialize with the correct factory address', async function () {
      // Test initialization with factory
    });
  });

  describe('User Creation', function () {
    it('should create a new user and account', async function () {
      // Test createUser
    });

    it('should generate a unique user ID', async function () {
      // Test user ID generation
    });

    it('should link the initial key to the account', async function () {
      // Test key linking
    });

    it('should emit the correct events', async function () {
      // Test event emission
    });

    it('should revert if key is already linked to another account', async function () {
      // Test key already linked error
    });
  });

  describe('User and Account Lookup', function () {
    it('should allow retrieving user info by ID', async function () {
      // Test getUser
    });

    it('should allow retrieving user ID by account address', async function () {
      // Test getUserIdByAccount
    });

    it('should revert when looking up non-existent user', async function () {
      // Test user not found error
    });
  });

  describe('Key Management', function () {
    describe('Key Linking Checks', function () {
      it('should correctly determine if a key is linked', async function () {
        // Test isKeyLinked
      });

      it('should return the correct linked account for a key', async function () {
        // Test returned account from isKeyLinked
      });
    });

    describe('Key Request Creation', function () {
      it('should create key requests for existing accounts', async function () {
        // Test requestAddKey
      });

      it('should revert for non-existent accounts', async function () {
        // Test account not registered error
      });

      it('should revert if key is already linked', async function () {
        // Test key already linked error
      });

      it('should emit the correct event', async function () {
        // Test KeyRequestCreated event
      });
    });

    describe('Key Addition Notification', function () {
      it('should allow registered accounts to notify key addition', async function () {
        // Test notifyKeyAdded
      });

      it('should revert if non-account tries to notify', async function () {
        // Test onlyRegisteredAccount modifier
      });

      it('should update the key-account mapping', async function () {
        // Test key mapping update
      });

      it('should emit the correct event', async function () {
        // Test KeyLinked event
      });
    });

    describe('Key Removal Notification', function () {
      it('should allow registered accounts to notify key removal', async function () {
        // Test notifyKeyRemoved
      });

      it('should revert if key was not linked to the account', async function () {
        // Test KeyNotFound error
      });

      it('should remove the key-account mapping', async function () {
        // Test key mapping removal
      });
    });
  });

  describe('Integration with Account Contract', function () {
    it('should create an account with the correct initial key', async function () {
      // Test initial key setup
    });

    it('should handle the full key request and approval flow', async function () {
      // Test end-to-end key addition flow
    });

    it('should handle the full key removal flow', async function () {
      // Test end-to-end key removal flow
    });

    it('should prevent the same key from being used in multiple accounts', async function () {
      // Test key reuse prevention
    });
  });
});
