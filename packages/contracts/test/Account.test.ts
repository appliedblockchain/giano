import { encodeChallenge } from '@appliedblockchain/giano-common';
import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';
import type { Account, AccountRegistry } from '../typechain-types';
import type { HexifiedPublicKey, KeyPair } from './helpers/testSetup';
import { deployContracts, generateTestKeypair } from './helpers/testSetup';
import { signWebAuthnChallenge } from './utils';

// Helper function to create and get an account instance
async function createAndGetAccount(
  adminKeypair: { publicKey: HexifiedPublicKey },
  accountRegistry: AccountRegistry,
): Promise<Account> {
  // Create a new account with the admin keypair through the registry
  const tx = await accountRegistry.createUser(adminKeypair.publicKey);
  const receipt = await tx.wait();

  // Get the account address from the event logs
  const userCreatedEvents = receipt?.logs
    .map((log) => {
      try {
        return accountRegistry.interface.parseLog({ topics: log.topics, data: log.data });
      } catch (e) {
        return null;
      }
    })
    .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'UserCreated');

  if (!userCreatedEvents?.length || !userCreatedEvents[0].args) {
    throw new Error('UserCreated event not found');
  }

  const accountAddress = userCreatedEvents[0].args.account;
  return await ethers.getContractAt('Account', accountAddress);
}

describe('Account Contract', function () {
  beforeEach(async () => {
    await loadFixture(deployContracts);
  });

  describe('Initialization', function () {
    it('should initialize with correct registry address', async function () {
      // Deploy a new account using the factory from the fixture
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Verify the registry is set correctly
      expect(await account.registry()).to.equal(await accountRegistry.getAddress());
    });

    it('should set up the initial admin key correctly', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Check the key exists and has admin role (role=2)
      const keyInfo = await account.getKeyInfo(adminKeypair.publicKey);
      expect(keyInfo.publicKey.x).to.equal(adminKeypair.publicKey.x);
      expect(keyInfo.publicKey.y).to.equal(adminKeypair.publicKey.y);
      expect(keyInfo.role).to.equal(2); // Role.ADMIN = 2
    });

    it('should start with admin key count of 1', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      expect(await account.getAdminKeyCount()).to.equal(1);
    });

    it('should start with nonces at 0', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      expect(await account.getNonce()).to.equal(0); // Transaction nonce
      expect(await account.getAdminNonce()).to.equal(0); // Admin nonce
    });

    it('should not be paused initially', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const [isPaused, pausedUntil] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntil).to.equal(0);
    });
  });

  describe('Key Management', function () {
    describe('Key Requests', function () {
      it('should allow registry to request adding a key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key with EXECUTOR role
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Verify the request was created by checking the emitted event
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        expect(keyRequestedEvents?.length).to.be.greaterThan(0);
        expect(keyRequestedEvents?.[0].args.x).to.equal(executorKeypair.publicKey.x);
        expect(keyRequestedEvents?.[0].args.y).to.equal(executorKeypair.publicKey.y);
        expect(keyRequestedEvents?.[0].args.requestedRole).to.equal(1); // Role.EXECUTOR = 1
      });

      it('should emit KeyRequested event with correct parameters', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key and check for event
        await expect(
          accountRegistry.requestAddKey(
            accountAddress,
            executorKeypair.publicKey,
            1, // Role.EXECUTOR = 1
          ),
        )
          .to.emit(account, 'KeyRequested')
          .withArgs(
            // We can't predict the exact requestId, so we use a matcher function
            (requestId: string) => ethers.isHexString(requestId, 32), // 32 bytes
            executorKeypair.publicKey.x,
            executorKeypair.publicKey.y,
            1, // Role.EXECUTOR = 1
          );
      });

      it('should reject requests for keys that already exist', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Try to request adding the same admin key again
        await expect(
          accountRegistry.requestAddKey(
            accountAddress,
            adminKeypair.publicKey,
            2, // Role.ADMIN = 2
          ),
        ).to.be.revertedWithCustomError(accountRegistry, 'KeyAlreadyLinked');
      });

      it('should only allow registry to request keys', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, user1 } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Try to call requestAddKey directly on the account contract from a non-registry address
        await expect(
          account.connect(user1).requestAddKey(
            executorKeypair.publicKey,
            1, // Role.EXECUTOR = 1
          ),
        ).to.be.revertedWithCustomError(account, 'OnlyRegistryCanAddKeys');
      });

      it('should generate unique request IDs', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding two different keys
        const tx1 = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const tx2 = await accountRegistry.requestAddKey(
          accountAddress,
          userKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request IDs from the events
        const receipt1 = await tx1.wait();
        const receipt2 = await tx2.wait();

        const keyRequestedEvents1 = receipt1?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const keyRequestedEvents2 = receipt2?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        expect(keyRequestedEvents1?.length).to.be.greaterThan(0);
        expect(keyRequestedEvents2?.length).to.be.greaterThan(0);

        const requestId1 = keyRequestedEvents1?.[0].args.requestId;
        const requestId2 = keyRequestedEvents2?.[0].args.requestId;

        // Verify the request IDs are different
        expect(requestId1).to.not.equal(requestId2);
      });
    });

    describe('Key Request Approval', function () {
      it('should add a key when request is approved by admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID from the emitted event
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.approveKeyRequest(requestId, adminAction);

        const keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1
      });

      it('should increment admin key count when adding admin key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Initial admin key count should be 1
        const initialAdminKeyCount = await account.getAdminKeyCount();
        expect(initialAdminKeyCount).to.equal(1);

        // Request adding a new admin key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the request
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash using the contract's function
        const challengeHash = await account.getAdminChallenge(adminAction);

        // Create signature using the challenge hash
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.approveKeyRequest(requestId, adminAction);

        // Verify admin key count increased
        const newAdminKeyCount = await account.getAdminKeyCount();
        expect(newAdminKeyCount).to.equal(2);
      });

      it('should emit KeyRequestApproved and KeyAdded events', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Prepare approval
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash using the contract's function
        const challengeHash = await account.getAdminChallenge(adminAction);

        // Create signature using the challenge hash
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Verify events are emitted
        await expect(account.approveKeyRequest(requestId, adminAction))
          .to.emit(account, 'KeyRequestApproved')
          .withArgs(requestId, executorKeypair.publicKey.x, executorKeypair.publicKey.y, 1) // Role.EXECUTOR = 1
          .and.to.emit(account, 'KeyAdded')
          .withArgs(executorKeypair.publicKey.x, executorKeypair.publicKey.y, 1); // Role.EXECUTOR = 1
      });

      it('should remove the key request after approval', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the request
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object for the first approval
        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and sign the first action
        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.approveKeyRequest(requestId, adminAction);

        // Try to approve the same request again - should fail because it was removed
        const newAdminNonce = await account.getAdminNonce();

        // Create the AdminAction object for the second attempt
        const newAdminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(newAdminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and sign the second action
        const newChallengeHash = await account.getAdminChallenge(newAdminAction);
        newAdminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(newChallengeHash)),
        );

        await expect(account.approveKeyRequest(requestId, newAdminAction))
          .to.be.revertedWithCustomError(account, 'RequestDoesNotExist')
          .withArgs(requestId);
      });

      it('should notify registry about the added key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the request
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and create signature
        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Check the registry is notified (KeyLinked event is emitted)
        await expect(account.approveKeyRequest(requestId, adminAction)).to.emit(accountRegistry, 'KeyLinked');

        // Verify the key is linked in the registry
        const [isLinked, linkedAccount] = await accountRegistry.isKeyLinked(executorKeypair.publicKey);
        expect(isLinked).to.be.true;
        expect(linkedAccount).to.equal(accountAddress);
      });

      it('should only allow approved requests with valid signatures', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Try to approve with a non-admin signature
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and sign with non-admin keypair
        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          userKeypair.publicKey,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.approveKeyRequest(requestId, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidAdminSignature',
        );
      });

      it('should validate operation data matches request ID', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding two different keys
        const tx1 = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const tx2 = await accountRegistry.requestAddKey(
          accountAddress,
          userKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request IDs
        const receipt1 = await tx1.wait();
        const keyRequestedEvents1 = receipt1?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const receipt2 = await tx2.wait();
        const keyRequestedEvents2 = receipt2?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId1 = keyRequestedEvents1?.[0].args.requestId;
        const requestId2 = keyRequestedEvents2?.[0].args.requestId;

        // Try to approve requestId1 but provide requestId2 in the operation data
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId2]);

        // Create the AdminAction object with mismatched data
        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and create signature
        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.approveKeyRequest(requestId1, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidOperationData',
        );
      });
    });

    describe('Key Request Rejection', function () {
      it('should reject a key request when called by admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID from the emitted event
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Prepare the admin action to reject the key request
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = {
          operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Reject the key request
        await account.rejectKeyRequest(requestId, adminAction);

        // Verify the key was not added
        const keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(0); // Role.NONE = 0
      });

      it('should emit KeyRequestRejected event', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Prepare admin action
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = {
          operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.rejectKeyRequest(requestId, adminAction))
          .to.emit(account, 'KeyRequestRejected')
          .withArgs(requestId);
      });

      it('should remove the key request after rejection', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Prepare admin action for rejection
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = {
          operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Reject the key request
        await account.rejectKeyRequest(requestId, adminAction);

        // Try to reject the same request again - should fail because it was removed
        const newAdminNonce = await account.getAdminNonce();
        const newOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const newAdminAction = {
          operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1
          operationData: newOperationData,
          nonce: Number(newAdminNonce),
          signature: '0x', // Will be set below
        };

        const newChallengeHash = await account.getAdminChallenge(newAdminAction);
        newAdminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(newChallengeHash)),
        );

        await expect(account.rejectKeyRequest(requestId, newAdminAction))
          .to.be.revertedWithCustomError(account, 'RequestDoesNotExist')
          .withArgs(requestId);
      });

      it('should fail when request does not exist', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Create a non-existent request ID
        const nonExistentRequestId = ethers.keccak256(ethers.toUtf8Bytes('non-existent-request'));

        // Prepare admin action
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [nonExistentRequestId]);

        const adminAction = {
          operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Attempt to reject a non-existent request
        await expect(account.rejectKeyRequest(nonExistentRequestId, adminAction))
          .to.be.revertedWithCustomError(account, 'RequestDoesNotExist')
          .withArgs(nonExistentRequestId);
      });

      it('should only allow rejection with valid admin signature', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Prepare admin action with non-admin signature
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = {
          operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        // Sign with a non-admin keypair
        adminAction.signature = encodeChallenge(
          userKeypair.publicKey,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Attempt to reject with invalid signature
        await expect(account.rejectKeyRequest(requestId, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidAdminSignature',
        );
      });
    });

    describe('Key Removal', function () {
      it('should remove an existing key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // First add a new key through request/approval flow
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Verify the key was added
        let keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1

        // Now remove the key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.removeKey(executorKeypair.publicKey, adminAction);

        // Verify the key was removed
        keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(0); // Role.NONE = 0
      });

      it('should fail to remove a non-existent key', async function () {
        const { accountRegistry, adminKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Attempt to remove a key that doesn't exist
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[userKeypair.publicKey.x, userKeypair.publicKey.y]],
        );

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.removeKey(userKeypair.publicKey, adminAction))
          .to.be.revertedWithCustomError(account, 'KeyDoesNotExist')
          .withArgs(userKeypair.publicKey.x, userKeypair.publicKey.y);
      });

      it('should decrement admin key count when removing admin key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add a new admin key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Verify two admin keys are present
        expect(await account.getAdminKeyCount()).to.equal(2);

        // Now remove the second admin key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.removeKey(executorKeypair.publicKey, adminAction);

        // Verify the admin key count decreased
        expect(await account.getAdminKeyCount()).to.equal(1);
      });

      it('should prevent removing the last admin key', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Verify only one admin key exists
        expect(await account.getAdminKeyCount()).to.equal(1);

        // Try to remove the only admin key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[adminKeypair.publicKey.x, adminKeypair.publicKey.y]],
        );

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.removeKey(adminKeypair.publicKey, adminAction)).to.be.revertedWithCustomError(
          account,
          'LastAdminKey',
        );
      });

      it('should emit KeyRemoved event', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and create signature
        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Prepare to remove the key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const removeAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x',
        };

        const challengeHash = await account.getAdminChallenge(removeAction);
        removeAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.removeKey(executorKeypair.publicKey, removeAction))
          .to.emit(account, 'KeyRemoved')
          .withArgs(executorKeypair.publicKey.x, executorKeypair.publicKey.y);
      });

      it('should notify registry about the removed key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and create signature
        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Verify the key exists in the registry
        const [isLinked, linkedAccount] = await accountRegistry.isKeyLinked(executorKeypair.publicKey);
        expect(isLinked).to.be.true;
        expect(linkedAccount).to.equal(accountAddress);

        // Prepare to remove the key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const removeAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(removeAction);
        removeAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Verify the registry's KeyUnlinked event is emitted
        await expect(account.removeKey(executorKeypair.publicKey, removeAction)).to.emit(
          accountRegistry,
          'KeyUnlinked',
        );

        // Verify the key is no longer linked in the registry
        const [isStillLinked, _] = await accountRegistry.isKeyLinked(executorKeypair.publicKey);
        expect(isStillLinked).to.be.false;
      });

      it('should only allow removal with valid admin signature', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add a new key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        // Create the AdminAction object
        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        // Get the challenge hash and create signature
        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Prepare to remove the key with a non-admin signature
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_KEY = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        // Sign with a non-admin key
        adminAction.signature = encodeChallenge(
          userKeypair.publicKey,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Should revert when using a non-admin signature
        await expect(account.removeKey(executorKeypair.publicKey, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidAdminSignature',
        );
      });
    });

    describe('Key Role Changes', function () {
      it('should change role of an existing key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add an executor key first
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Verify current role is EXECUTOR
        let keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1

        // Now change the role to ADMIN
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.changeKeyRole(executorKeypair.publicKey, 2, adminAction); // Role.ADMIN = 2

        // Verify role changed to ADMIN
        keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(2); // Role.ADMIN = 2
      });

      it('should fail to change role of a non-existent key', async function () {
        const { accountRegistry, adminKeypair, userKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Try to change role of a non-existent key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[userKeypair.publicKey.x, userKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.changeKeyRole(userKeypair.publicKey, 2, adminAction))
          .to.be.revertedWithCustomError(account, 'KeyDoesNotExist')
          .withArgs(userKeypair.publicKey.x, userKeypair.publicKey.y);
      });

      it('should increment admin key count when upgrading to admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Initial admin key count
        const initialAdminKeyCount = await account.getAdminKeyCount();
        expect(initialAdminKeyCount).to.equal(1);

        // Add an executor key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Verify admin key count unchanged
        expect(await account.getAdminKeyCount()).to.equal(1);

        // Now upgrade the executor key to admin
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.changeKeyRole(executorKeypair.publicKey, 2, adminAction); // Role.ADMIN = 2

        // Verify admin key count increased
        expect(await account.getAdminKeyCount()).to.equal(2);
      });

      it('should decrement admin key count when downgrading from admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add a second admin key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Verify there are now 2 admin keys
        expect(await account.getAdminKeyCount()).to.equal(2);

        // Now downgrade the new admin key to executor
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 1], // Role.EXECUTOR = 1
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.changeKeyRole(executorKeypair.publicKey, 1, adminAction); // Role.EXECUTOR = 1

        // Verify admin key count decreased
        expect(await account.getAdminKeyCount()).to.equal(1);
      });

      it('should prevent downgrading the last admin key', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Verify only one admin key exists
        expect(await account.getAdminKeyCount()).to.equal(1);

        // Try to downgrade the only admin key
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[adminKeypair.publicKey.x, adminKeypair.publicKey.y], 1], // Role.EXECUTOR = 1
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.changeKeyRole(adminKeypair.publicKey, 1, adminAction)).to.be.revertedWithCustomError(
          account,
          'LastAdminKey',
        );
      });

      it('should emit KeyRoleChanged event', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add an executor key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Prepare to change role
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Verify event is emitted
        await expect(account.changeKeyRole(executorKeypair.publicKey, 2, adminAction))
          .to.emit(account, 'KeyRoleChanged')
          .withArgs(executorKeypair.publicKey.x, executorKeypair.publicKey.y, 2); // Role.ADMIN = 2
      });

      it('should validate operation data matches key and new role', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        // Create an account
        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        // Add an executor key
        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const approveNonce = await account.getAdminNonce();
        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData: approveOperationData,
          nonce: Number(approveNonce),
          signature: '0x', // Will be set below
        };

        const approveChallenge = await account.getAdminChallenge(approveAction);
        approveAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(approveChallenge)),
        );

        await account.approveKeyRequest(requestId, approveAction);

        // Prepare operation data with incorrect role (passing EXECUTOR=1 in operationData but ADMIN=2 in function call)
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 1], // Role.EXECUTOR = 1 (incorrect)
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Should revert due to mismatched operationData
        await expect(account.changeKeyRole(executorKeypair.publicKey, 2, adminAction)) // Role.ADMIN = 2
          .to.be.revertedWithCustomError(account, 'InvalidOperationData');
      });
    });
  });

  describe('Transaction Execution', function () {
    describe('Single Transactions', function () {
      it('should execute a transaction with valid signature', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare the transaction to set a value in the test contract
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        // Get the challenge hash and create the signature
        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Execute the transaction
        await account.execute({ call, signature });

        // Verify the value was set in the test contract
        expect(await testContract.value()).to.equal(42);
        expect(await testContract.lastCaller()).to.equal(await account.getAddress());
      });

      it('should reject execution with invalid signature', async function () {
        const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare the transaction to set a value in the test contract
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        // Get the challenge hash but sign with the wrong key
        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
        const signature = encodeChallenge(userKeypair.publicKey, webAuthnSignature);

        // The transaction should be rejected
        await expect(account.execute({ call, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should increment nonce after successful execution', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Check initial nonce
        expect(await account.getNonce()).to.equal(0);

        // Prepare and execute a transaction
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        await account.execute({ call, signature });

        // Verify nonce was incremented
        expect(await account.getNonce()).to.equal(1);
      });

      it('should emit Executed event', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare transaction data
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Verify the event is emitted with correct parameters
        await expect(account.execute({ call, signature }))
          .to.emit(account, 'Executed')
          .withArgs(0, await testContract.getAddress(), 0, callData);
      });

      it('should pass correct value to target contract', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Fund the account
        await ethers.provider.send('hardhat_setBalance', [
          await account.getAddress(),
          '0x1000000000000000000', // 1 ETH
        ]);

        // Prepare the deposit transaction with ETH value
        const callData = testContract.interface.encodeFunctionData('deposit');
        const ethToSend = ethers.parseEther('0.5');
        const call = {
          target: await testContract.getAddress(),
          value: ethToSend,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Execute the deposit
        await account.execute({ call, signature });

        // Verify the value was correctly sent
        expect(await testContract.balances(await account.getAddress())).to.equal(ethToSend);
      });

      it('should forward revert reasons from target contracts', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare a transaction that will revert
        const errorMessage = 'This operation will fail';
        const callData = testContract.interface.encodeFunctionData('willRevert', [errorMessage]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // The error should be passed through from the target contract
        await expect(account.execute({ call, signature })).to.be.revertedWith(errorMessage);
      });

      it('should prevent execution when paused', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Pause the account first
        const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
        const adminAction = {
          operation: 4, // PAUSE_ACCOUNT
          operationData: pauseData,
          nonce: 0,
          signature: '0x',
        };

        // Sign the admin action
        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Pause the account
        await account.pauseAccount(pauseUntil, adminAction);

        // Now try to execute a transaction
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const txChallengeHash = await account.getChallenge(call);
        const txWebAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(txChallengeHash),
        );
        const txSignature = encodeChallenge(adminKeypair.publicKey, txWebAuthnSignature);

        // The transaction should be rejected because the account is paused
        await expect(account.execute({ call, signature: txSignature }))
          .to.be.revertedWithCustomError(account, 'AccountIsPaused')
          .withArgs(pauseUntil);
      });
    });

    describe('Batch Transactions', function () {
      it('should execute multiple transactions in one call', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare multiple calls
        const setValue = {
          target: await testContract.getAddress(),
          value: 0n,
          data: testContract.interface.encodeFunctionData('setValue', [42]),
        };

        const setMessage = {
          target: await testContract.getAddress(),
          value: 0n,
          data: testContract.interface.encodeFunctionData('setMessage', ['Hello from batch']),
        };

        const calls = [setValue, setMessage];

        // Get the batch challenge hash and create the signature
        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Execute the batch transaction
        await account.executeBatch({ calls, signature });

        // Verify both operations were executed
        expect(await testContract.value()).to.equal(42);
        expect(await testContract.message()).to.equal('Hello from batch');
        expect(await testContract.lastCaller()).to.equal(await account.getAddress());
      });

      it('should validate batch challenge correctly', async function () {
        const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare batch calls
        const calls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [42]),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Hello from batch']),
          },
        ];

        // Create a modified batch with different calls
        const modifiedCalls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [100]), // Different value
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Different message']),
          },
        ];

        // Sign the original batch but try to execute with modified calls
        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // This should fail because the challenge hash won't match
        await expect(account.executeBatch({ calls: modifiedCalls, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should reject with invalid signature', async function () {
        const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare batch calls
        const calls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [42]),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Hello from batch']),
          },
        ];

        // Get the challenge hash but sign with the wrong key
        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
        const signature = encodeChallenge(userKeypair.publicKey, webAuthnSignature);

        // Should be rejected because userKeypair isn't authorized for this account
        await expect(account.executeBatch({ calls, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should increment nonce only once for the batch', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Check initial nonce
        expect(await account.getNonce()).to.equal(0);

        // Prepare multiple calls
        const calls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [42]),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Hello from batch']),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [100]),
          },
        ];

        // Sign and execute batch
        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        await account.executeBatch({ calls, signature });

        // Verify nonce was incremented only once, despite multiple calls
        expect(await account.getNonce()).to.equal(1);
      });

      it('should emit one Executed event for the batch', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare multiple calls
        const calls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [42]),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Hello from batch']),
          },
        ];

        // Sign batch
        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Create a transaction to check events
        const tx = await account.executeBatch({ calls, signature });
        const receipt = await tx.wait();
        expect(receipt).to.not.be.null;

        // Find and verify the Executed event
        const accountAddress = await account.getAddress();
        const logs = receipt?.logs || [];
        const executedEvents = logs
          .filter((log) => log.address === accountAddress)
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter(
            (event): event is NonNullable<ReturnType<typeof account.interface.parseLog>> =>
              event !== null && event.name === 'Executed',
          );

        // Verify we found the event
        expect(executedEvents.length).to.equal(1);
        const executedEvent = executedEvents[0];

        // Verify the event parameters
        expect(executedEvent.args.nonce).to.equal(0);
        expect(executedEvent.args.target).to.equal(ethers.ZeroAddress);
        expect(executedEvent.args.value).to.equal(0);
        // We don't check the exact data as it's the encoded batch that's complex to match
        expect(executedEvent.args.data).to.not.be.null;
      });

      it('should revert entire batch if one call fails', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Prepare calls with one that will fail
        const calls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [42]),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('willRevert', ['Intentional failure']),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Should not be set']),
          },
        ];

        // Sign batch
        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Execution should revert with the error from the failing call
        await expect(account.executeBatch({ calls, signature })).to.be.revertedWith('Intentional failure');

        // Verify the first call was rolled back
        expect(await testContract.value()).to.equal(0); // Not 42
      });

      it('should prevent execution when paused', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        // Create a new account with the admin key
        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        // Pause the account first
        const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
        const adminAction = {
          operation: 4, // PAUSE_ACCOUNT
          operationData: pauseData,
          nonce: 0,
          signature: '0x',
        };

        // Sign the admin action
        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        // Pause the account
        await account.pauseAccount(pauseUntil, adminAction);

        // Prepare batch calls
        const calls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setValue', [42]),
          },
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: testContract.interface.encodeFunctionData('setMessage', ['Hello from batch']),
          },
        ];

        // Sign batch
        const batchChallengeHash = await account.getBatchChallenge(calls);
        const batchSignature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(batchChallengeHash)),
        );

        // Batch execution should be rejected because the account is paused
        await expect(account.executeBatch({ calls, signature: batchSignature }))
          .to.be.revertedWithCustomError(account, 'AccountIsPaused')
          .withArgs(pauseUntil);
      });
    });
  });

  describe('Admin Operations', function () {
    it('should validate admin signatures correctly', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      // Create an account
      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      // Request adding a new key (we need a request ID to test admin operations)
      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Get the request ID from events
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Create admin action for approving the key request
      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData,
        nonce: Number(adminNonce),
        signature: '0x', // Will be set below
      };

      // Get challenge hash and sign it
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // The operation should succeed with a valid admin signature
      await expect(account.approveKeyRequest(requestId, adminAction)).to.not.be.reverted;

      // Verify the key was added
      const keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
      expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1
    });

    it('should increment admin nonce after operations', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      // Create an account
      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      // Get the initial admin nonce
      const initialAdminNonce = await account.getAdminNonce();
      expect(initialAdminNonce).to.equal(0);

      // Request adding a new key
      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Get the request ID
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Create admin action
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData,
        nonce: Number(initialAdminNonce),
        signature: '0x',
      };

      // Sign the action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Execute the admin operation
      await account.approveKeyRequest(requestId, adminAction);

      // Check that the admin nonce incremented
      const newAdminNonce = await account.getAdminNonce();
      expect(newAdminNonce).to.equal(1);

      // Request adding another key to test nonce incrementing again
      const tx2 = await accountRegistry.requestAddKey(
        accountAddress,
        { x: ethers.hexlify(ethers.randomBytes(32)), y: ethers.hexlify(ethers.randomBytes(32)) },
        1, // Role.EXECUTOR = 1
      );

      // Get the second request ID
      const receipt2 = await tx2.wait();
      const keyRequestedEvents2 = receipt2?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId2 = keyRequestedEvents2?.[0].args.requestId;

      // Create second admin action
      const operationData2 = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId2]);
      const adminAction2 = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData: operationData2,
        nonce: Number(newAdminNonce),
        signature: '0x',
      };

      // Sign the second action
      const challengeHash2 = await account.getAdminChallenge(adminAction2);
      adminAction2.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash2)),
      );

      // Execute the second admin operation
      await account.approveKeyRequest(requestId2, adminAction2);

      // Check that the admin nonce incremented again
      const finalAdminNonce = await account.getAdminNonce();
      expect(finalAdminNonce).to.equal(2);
    });

    it('should emit AdminActionExecuted event', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      // Create an account
      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      // Request adding a new key
      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Get the request ID
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Create admin action
      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Verify AdminActionExecuted event is emitted with correct parameters
      await expect(account.approveKeyRequest(requestId, adminAction))
        .to.emit(account, 'AdminActionExecuted')
        .withArgs(0, adminNonce); // AdminOperation.APPROVE_KEY_REQUEST = 0
    });

    it('should reject operations with invalid nonce', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      // Create an account
      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      // Request adding a new key
      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Get the request ID
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Get the current admin nonce
      const adminNonce = await account.getAdminNonce();

      // Create admin action with incorrect nonce (current nonce + 1)
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData,
        nonce: Number(adminNonce) + 1, // Incorrect nonce
        signature: '0x',
      };

      // Sign the action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Verify operation is rejected with InvalidNonce error
      await expect(account.approveKeyRequest(requestId, adminAction))
        .to.be.revertedWithCustomError(account, 'InvalidNonce')
        .withArgs(adminNonce, Number(adminNonce) + 1);
    });

    it('should reject operations with wrong operation type', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      // Create an account
      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      // Request adding a new key
      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Get the request ID
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Get the current admin nonce
      const adminNonce = await account.getAdminNonce();

      // Create admin action with wrong operation type (REJECT_KEY_REQUEST instead of APPROVE_KEY_REQUEST)
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = {
        operation: 1, // AdminOperation.REJECT_KEY_REQUEST = 1 (Wrong operation type)
        operationData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Verify operation is rejected with InvalidOperation error
      await expect(account.approveKeyRequest(requestId, adminAction))
        .to.be.revertedWithCustomError(account, 'InvalidOperation')
        .withArgs(0, 1); // Expected APPROVE_KEY_REQUEST=0, got REJECT_KEY_REQUEST=1
    });

    it('should reject operations with invalid signature', async function () {
      const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

      // Create an account
      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      // Request adding a new key
      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Get the request ID
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Get the current admin nonce
      const adminNonce = await account.getAdminNonce();

      // Create admin action
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Get challenge hash but sign it with a non-admin key
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        userKeypair.publicKey, // Non-admin key
        signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Verify operation is rejected with InvalidAdminSignature error
      await expect(account.approveKeyRequest(requestId, adminAction)).to.be.revertedWithCustomError(
        account,
        'InvalidAdminSignature',
      );
    });
  });

  describe('Pause Functionality', function () {
    it('should allow admin to pause the account', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Prepare pause data - pause for 1 hour
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600;
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x', // Will be set below
      };

      // Get the challenge hash and sign it
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Pause the account - should not revert
      await expect(account.pauseAccount(pauseUntil, adminAction)).to.not.be.reverted;

      // Verify account is paused
      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.true;
      expect(pausedUntilTime).to.equal(pauseUntil);
    });

    it('should emit AccountPaused event with correct timestamp', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Prepare pause data
      const pauseUntil = Math.floor(Date.now() / 1000) + 7200; // 2 hours from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the admin action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Verify the AccountPaused event is emitted with the correct timestamp
      await expect(account.pauseAccount(pauseUntil, adminAction))
        .to.emit(account, 'AccountPaused')
        .withArgs(pauseUntil);
    });

    it('should prevent transaction execution while paused', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Pause the account first
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the admin action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Pause the account
      await account.pauseAccount(pauseUntil, adminAction);

      // Now try to execute a transaction
      const callData = testContract.interface.encodeFunctionData('setValue', [42]);
      const call = {
        target: await testContract.getAddress(),
        value: 0n,
        data: callData,
      };

      const txChallengeHash = await account.getChallenge(call);
      const txWebAuthnSignature = signWebAuthnChallenge(
        adminKeypair.keyPair.privateKey,
        ethers.getBytes(txChallengeHash),
      );
      const txSignature = encodeChallenge(adminKeypair.publicKey, txWebAuthnSignature);

      // The transaction should be rejected because the account is paused
      await expect(account.execute({ call, signature: txSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(pauseUntil);

      // Batch execution should also be rejected
      const batchChallengeHash = await account.getBatchChallenge([call]);
      const batchWebAuthnSignature = signWebAuthnChallenge(
        adminKeypair.keyPair.privateKey,
        ethers.getBytes(batchChallengeHash),
      );
      const batchSignature = encodeChallenge(adminKeypair.publicKey, batchWebAuthnSignature);

      await expect(account.executeBatch({ calls: [call], signature: batchSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(pauseUntil);
    });

    it('should handle indefinite pausing', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Pause the account indefinitely (0 means indefinite)
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [0]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the admin action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Pause the account indefinitely
      await account.pauseAccount(0, adminAction);

      // Verify account is paused indefinitely (max uint256 value)
      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.true;
      expect(pausedUntilTime).to.equal(ethers.MaxUint256);

      // Try to execute a transaction
      const callData = testContract.interface.encodeFunctionData('setValue', [42]);
      const call = {
        target: await testContract.getAddress(),
        value: 0n,
        data: callData,
      };

      const txChallengeHash = await account.getChallenge(call);
      const txWebAuthnSignature = signWebAuthnChallenge(
        adminKeypair.keyPair.privateKey,
        ethers.getBytes(txChallengeHash),
      );
      const txSignature = encodeChallenge(adminKeypair.publicKey, txWebAuthnSignature);

      // The transaction should be rejected with AccountIsPaused error and max uint256 value
      await expect(account.execute({ call, signature: txSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(ethers.MaxUint256);
    });

    it('should allow admin to unpause the account', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Pause the account first
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      let adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the pause action
      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      // Pause the account
      await account.pauseAccount(pauseUntil, pauseAction);

      // Now unpause the account
      adminNonce = await account.getAdminNonce();
      const unpauseAction = {
        operation: 5, // AdminOperation.UNPAUSE_ACCOUNT = 5
        operationData: '0x', // No data needed for unpause
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the unpause action
      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      // Unpause the account - should not revert
      await expect(account.unpauseAccount(unpauseAction)).to.not.be.reverted;

      // Verify account is no longer paused
      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntilTime).to.equal(0);
    });

    it('should emit AccountUnpaused event', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Pause the account first
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      let adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the pause action
      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      // Pause the account
      await account.pauseAccount(pauseUntil, pauseAction);

      // Now unpause the account and check for the event
      adminNonce = await account.getAdminNonce();
      const unpauseAction = {
        operation: 5, // AdminOperation.UNPAUSE_ACCOUNT = 5
        operationData: '0x', // No data needed for unpause
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the unpause action
      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      // Verify the AccountUnpaused event is emitted
      await expect(account.unpauseAccount(unpauseAction)).to.emit(account, 'AccountUnpaused');
    });

    it('should allow transaction execution after unpausing', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Pause the account first
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      let adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the pause action
      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      // Pause the account
      await account.pauseAccount(pauseUntil, pauseAction);

      // Now unpause the account
      adminNonce = await account.getAdminNonce();
      const unpauseAction = {
        operation: 5, // AdminOperation.UNPAUSE_ACCOUNT = 5
        operationData: '0x', // No data needed for unpause
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the unpause action
      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      // Unpause the account
      await account.unpauseAccount(unpauseAction);

      // Now execute a transaction - should work after unpausing
      const callData = testContract.interface.encodeFunctionData('setValue', [42]);
      const call = {
        target: await testContract.getAddress(),
        value: 0n,
        data: callData,
      };

      const txChallengeHash = await account.getChallenge(call);
      const txWebAuthnSignature = signWebAuthnChallenge(
        adminKeypair.keyPair.privateKey,
        ethers.getBytes(txChallengeHash),
      );
      const txSignature = encodeChallenge(adminKeypair.publicKey, txWebAuthnSignature);

      // The transaction should execute successfully
      await account.execute({ call, signature: txSignature });

      // Verify the value was set in the test contract
      expect(await testContract.value()).to.equal(42);
    });

    it('should report pause status correctly', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Initially the account should not be paused
      let [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntilTime).to.equal(0);

      // Pause the account
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      // Sign the pause action
      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      // Pause the account
      await account.pauseAccount(pauseUntil, pauseAction);

      // Now the account should be paused with the correct timestamp
      [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.true;
      expect(pausedUntilTime).to.equal(pauseUntil);
    });
  });

  describe('ERC Support', function () {
    describe('ERC1271 Implementation', function () {
      let account: Account;
      let adminKeypair: KeyPair;
      let executorKeypair: KeyPair;
      let nonAuthorizedKeypair: KeyPair;

      beforeEach(async function () {
        // Setup contracts and keys from the fixture
        const fixture = await loadFixture(deployContracts);
        adminKeypair = fixture.adminKeypair;

        // Generate additional test keypairs
        executorKeypair = generateTestKeypair();
        nonAuthorizedKeypair = generateTestKeypair();

        // Create account with admin key
        account = await createAndGetAccount(adminKeypair, fixture.accountRegistry);

        // Add an executor key through request/approval flow
        const accountAddress = await account.getAddress();

        // Request adding a new key
        const tx = await fixture.accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Get the request ID from the emitted event
        const receipt = await tx.wait();
        const keyRequestedEvents = receipt?.logs
          .map((log) => {
            try {
              return account.interface.parseLog({ topics: log.topics, data: log.data });
            } catch (e) {
              return null;
            }
          })
          .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        // Approve the key request
        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = {
          operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await account.approveKeyRequest(requestId, adminAction);
      });

      it('should return the ERC1271 magic value for a valid signature', async function () {
        // Create a message hash to sign
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        // Sign the message with the admin key
        const webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(messageHash));

        // Encode the signature with the public key
        const encodedSignature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Verify the signature using ERC1271 interface
        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        // Should return the magic value
        expect(isValid).to.equal('0x1626ba7e');
      });

      it('should return the magic value for a valid executor signature', async function () {
        // Create a message hash to sign
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello from executor!'));

        // Sign the message with the executor key
        const webAuthnSignature = signWebAuthnChallenge(
          executorKeypair.keyPair.privateKey,
          ethers.getBytes(messageHash),
        );

        // Encode the signature with the public key
        const encodedSignature = encodeChallenge(executorKeypair.publicKey, webAuthnSignature);

        // Verify the signature using ERC1271 interface
        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        // Should return the magic value
        expect(isValid).to.equal('0x1626ba7e');
      });

      it('should not return the magic value for an invalid signature', async function () {
        // Create a message hash to sign
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        // Create a different message hash (signed message doesn't match verified message)
        const differentMessageHash = ethers.keccak256(ethers.toUtf8Bytes('Different message!'));

        // Sign the different message with the admin key
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(differentMessageHash),
        );

        // Encode the signature with the public key
        const encodedSignature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        // Verify the signature using ERC1271 interface against the original message
        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        // Should not return the magic value
        expect(isValid).to.equal('0xffffffff');
      });

      it('should not return the magic value for a signature from unauthorized key', async function () {
        // Create a message hash to sign
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        // Sign the message with an unauthorized key
        const webAuthnSignature = signWebAuthnChallenge(
          nonAuthorizedKeypair.keyPair.privateKey,
          ethers.getBytes(messageHash),
        );

        // Encode the signature with the unauthorized public key
        const encodedSignature = encodeChallenge(nonAuthorizedKeypair.publicKey, webAuthnSignature);

        // Verify the signature using ERC1271 interface
        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        // Should not return the magic value since the key is not authorized
        expect(isValid).to.equal('0xffffffff');
      });
    });

    describe('ERC721/ERC1155 Receiver', function () {
      let account: Account;
      let adminKeypair: KeyPair;
      let accountRegistry: AccountRegistry;

      beforeEach(async function () {
        // Load the fixture and set up an account for testing
        const fixture = await loadFixture(deployContracts);
        adminKeypair = fixture.adminKeypair;
        accountRegistry = fixture.accountRegistry;
        account = await createAndGetAccount(adminKeypair, accountRegistry);
      });

      it('should implement onERC721Received correctly', async function () {
        // Get the ERC721Receiver interface selector
        const ERC721ReceiverSelector = '0x150b7a02'; // bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))

        // Call the onERC721Received function directly
        const result = await account.onERC721Received(ethers.ZeroAddress, ethers.ZeroAddress, 0, '0x');

        // Verify it returns the correct selector
        expect(result).to.equal(ERC721ReceiverSelector);
      });

      it('should implement onERC1155Received correctly', async function () {
        // Get the ERC1155Receiver interface selector for single token receipt
        const ERC1155ReceivedSelector = '0xf23a6e61'; // bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))

        // Call the onERC1155Received function directly
        const result = await account.onERC1155Received(ethers.ZeroAddress, ethers.ZeroAddress, 0, 1, '0x');

        // Verify it returns the correct selector
        expect(result).to.equal(ERC1155ReceivedSelector);
      });

      it('should implement onERC1155BatchReceived correctly', async function () {
        // Get the ERC1155Receiver interface selector for batch token receipt
        const ERC1155BatchReceivedSelector = '0xbc197c81'; // bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))

        // Call the onERC1155BatchReceived function directly
        const result = await account.onERC1155BatchReceived(ethers.ZeroAddress, ethers.ZeroAddress, [], [], '0x');

        // Verify it returns the correct selector
        expect(result).to.equal(ERC1155BatchReceivedSelector);
      });

      it('should support relevant interfaces', async function () {
        // Interface IDs
        const ERC721ReceiverInterfaceId = '0x150b7a02'; // IERC721Receiver
        const ERC1155ReceiverInterfaceId = '0x4e2312e0'; // IERC1155Receiver
        const ERC1271InterfaceId = '0x1626ba7e'; // IERC1271

        // Check that each interface is supported
        expect(await account.supportsInterface(ERC721ReceiverInterfaceId)).to.be.true;
        expect(await account.supportsInterface(ERC1155ReceiverInterfaceId)).to.be.true;
        expect(await account.supportsInterface(ERC1271InterfaceId)).to.be.true;

        // Check that a random interface ID is not supported
        const randomInterfaceId = '0x12345678';
        expect(await account.supportsInterface(randomInterfaceId)).to.be.false;
      });
    });
  });

  describe('Utility Functions', function () {
    let account: Account;
    let adminKeypair: KeyPair;
    let userKeypair: KeyPair;
    let accountRegistry: AccountRegistry;

    beforeEach(async function () {
      // Load the fixture and set up an account for testing
      const fixture = await loadFixture(deployContracts);
      adminKeypair = fixture.adminKeypair;
      accountRegistry = fixture.accountRegistry;
      account = await createAndGetAccount(adminKeypair, accountRegistry);
      userKeypair = generateTestKeypair();
    });

    it('should calculate challenge hash correctly for single calls', async function () {
      // Create a call to test
      const call = {
        target: ethers.ZeroAddress,
        value: 0n,
        data: '0x',
        nonce: await account.getNonce(),
      };

      // Calculate the expected challenge hash using the same method as the contract
      // In contract: keccak256(bytes.concat(bytes20(address(this)), bytes32(uint256(currentNonce)), bytes20(call.target), bytes32(call.value), call.data))
      const expectedHash = ethers.keccak256(
        ethers.concat([
          ethers.zeroPadValue(ethers.hexlify(account.target.toString()), 20),
          ethers.zeroPadValue(ethers.toBeHex(call.nonce), 32),
          ethers.zeroPadValue(ethers.hexlify(call.target.toString()), 20),
          ethers.zeroPadValue(ethers.toBeHex(call.value), 32),
          call.data || '0x',
        ]),
      );

      // Get the challenge hash from the contract
      const challengeHash = await account.getChallenge(call);

      // The hashes should match
      expect(challengeHash).to.equal(expectedHash);
    });

    it('should calculate challenge hash correctly for batch calls', async function () {
      // Create multiple calls to test
      const calls = [
        {
          target: ethers.ZeroAddress,
          value: 0n,
          data: '0x',
          nonce: await account.getNonce(),
        },
        {
          target: ethers.getAddress(ethers.hexlify(adminKeypair.publicKey.x).substring(0, 42)), // Using this as a dummy address
          value: 1000n,
          data: '0x123456',
          nonce: await account.getNonce(),
        },
      ];

      // Calculate the expected batch challenge hash using the same method as the contract
      // In contract:
      // 1. Create array of hashes for each call
      // 2. Final hash is keccak256(abi.encode(address(this), currentNonce, callHashes))
      const callHashes = calls.map((call) =>
        ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ['address', 'uint256', 'bytes'],
            [call.target, call.value, call.data],
          ),
        ),
      );

      const expectedHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['address', 'uint256', 'bytes32[]'],
          [account.target, calls[0].nonce, callHashes],
        ),
      );

      // Get the batch challenge hash from the contract
      const challengeHash = await account.getBatchChallenge(calls);

      // The hashes should match
      expect(challengeHash).to.equal(expectedHash);
    });

    it('should calculate admin challenge hash correctly', async function () {
      // Create an admin action to test
      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['tuple(bytes32 x, bytes32 y)'],
        [[userKeypair.publicKey.x, userKeypair.publicKey.y]],
      );

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        nonce: adminNonce,
        operationData,
        signature: '0x', // Empty signature for now
      };

      // Calculate the expected admin challenge hash using the same method as the contract
      // In contract: keccak256(abi.encodePacked(address(this), adminAction.operation, adminAction.operationData, adminAction.nonce))
      const expectedHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'uint8', 'bytes', 'uint256'],
          [account.target, adminAction.operation, adminAction.operationData, adminAction.nonce],
        ),
      );

      // Get the admin challenge hash from the contract
      const challengeHash = await account.getAdminChallenge(adminAction);

      // The hashes should match
      expect(challengeHash).to.equal(expectedHash);
    });

    it('should return correct key info for existing key', async function () {
      // Get key info for the admin key
      const keyInfo = await account.getKeyInfo(adminKeypair.publicKey);

      // Verify key info is correct
      expect(keyInfo.publicKey.x).to.equal(adminKeypair.publicKey.x);
      expect(keyInfo.publicKey.y).to.equal(adminKeypair.publicKey.y);
      expect(keyInfo.role).to.equal(2); // Role.ADMIN = 2
    });

    it('should return empty key info for non-existent key', async function () {
      // Get key info for a non-existent key
      const keyInfo = await account.getKeyInfo(userKeypair.publicKey);

      // Verify key info shows the key doesn't exist
      expect(keyInfo.role).to.equal(0); // Role.NONE = 0
    });

    it('should return correct admin nonce', async function () {
      // Get the initial admin nonce
      const initialNonce = await account.getAdminNonce();
      expect(initialNonce).to.equal(0);

      // Add a request to trigger a nonce increment
      const tx = await accountRegistry.requestAddKey(account.target, userKeypair.publicKey, 1); // Role.EXECUTOR = 1
      const receipt = await tx.wait();

      // Get the requestId from events
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      if (!keyRequestedEvents?.length) {
        throw new Error('KeyRequested event not found');
      }

      const requestId = keyRequestedEvents[0].args.requestId;

      // Create and sign an admin action
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        nonce: initialNonce,
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]),
        signature: '0x',
      };

      // Get the challenge hash and sign it
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Execute an admin operation to increment the nonce
      await account.approveKeyRequest(requestId, adminAction);

      // Get the nonce again, it should be incremented
      const newNonce = await account.getAdminNonce();
      expect(newNonce).to.equal(1);
    });

    it('should return correct transaction nonce', async function () {
      // Get the initial transaction nonce
      const initialNonce = await account.getNonce();
      expect(initialNonce).to.equal(0);

      // Create a call
      const call = {
        target: ethers.ZeroAddress,
        value: 0n,
        data: '0x',
        nonce: initialNonce,
      };

      // Sign the call
      const challengeHash = await account.getChallenge(call);
      const webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      // Execute the call to increment the nonce
      await account.execute({ call, signature });

      // Get the nonce again, it should be incremented
      const newNonce = await account.getNonce();
      expect(newNonce).to.equal(1);
    });

    it('should return correct admin key count', async function () {
      // Initially there should be one admin key
      expect(await account.getAdminKeyCount()).to.equal(1);

      // Create an executor key request
      const tx = await accountRegistry.requestAddKey(account.target, userKeypair.publicKey, 1); // Role.EXECUTOR = 1
      const receipt = await tx.wait();

      // Get the requestId from events
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      if (!keyRequestedEvents?.length) {
        throw new Error('KeyRequested event not found');
      }

      const requestId = keyRequestedEvents[0].args.requestId;

      // Create and sign an admin action to approve the key
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        nonce: await account.getAdminNonce(),
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]),
        signature: '0x',
      };

      // Get the challenge hash and sign it
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Approve the executor key
      await account.approveKeyRequest(requestId, adminAction);

      // Admin key count should still be 1
      expect(await account.getAdminKeyCount()).to.equal(1);

      // Now change the executor key to admin
      const changeKeyRoleAction = {
        operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
        nonce: await account.getAdminNonce(),
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[userKeypair.publicKey.x, userKeypair.publicKey.y], 2], // Role.ADMIN = 2
        ),
        signature: '0x',
      };

      // Sign the action
      const challengeHash2 = await account.getAdminChallenge(changeKeyRoleAction);
      changeKeyRoleAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash2)),
      );

      // Change role to admin
      await account.changeKeyRole(userKeypair.publicKey, 2, changeKeyRoleAction); // Role.ADMIN = 2

      // Admin key count should now be 2
      expect(await account.getAdminKeyCount()).to.equal(2);
    });

    it('should check if account is paused correctly', async function () {
      // Initially the account should not be paused
      const [isPausedInitial, untilInitial] = await account.isPaused();
      expect(isPausedInitial).to.be.false;
      expect(untilInitial).to.equal(0);

      // Create an admin action to pause the account
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        nonce: await account.getAdminNonce(),
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]),
        signature: '0x',
      };

      // Sign the admin action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Pause the account
      await account.pauseAccount(pauseUntil, adminAction);

      // Now the account should be paused
      const [isPausedAfter, untilAfter] = await account.isPaused();
      expect(isPausedAfter).to.be.true;
      expect(untilAfter).to.equal(pauseUntil);

      // Create an admin action to unpause the account
      const unpauseAction = {
        operation: 5, // AdminOperation.UNPAUSE_ACCOUNT = 5
        nonce: await account.getAdminNonce(),
        operationData: '0x', // No operation data needed for unpause
        signature: '0x',
      };

      // Sign the admin action
      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      // Unpause the account
      await account.unpauseAccount(unpauseAction);

      // Now the account should not be paused
      const [isPausedFinal, untilFinal] = await account.isPaused();
      expect(isPausedFinal).to.be.false;
      expect(untilFinal).to.equal(0);
    });
  });

  describe('Security Features', function () {
    it('should prevent reentrancy attacks', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Fund the account
      await ethers.provider.send('hardhat_setBalance', [account.target, ethers.toBeHex(ethers.parseEther('1.0'))]);

      // First deposit some ETH to the test contract from the account
      const depositCallData = testContract.interface.encodeFunctionData('deposit');
      const depositCall = {
        target: await testContract.getAddress(),
        value: ethers.parseEther('0.5'),
        data: depositCallData,
      };

      let challengeHash = await account.getChallenge(depositCall);
      let webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      let signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      // Execute the deposit
      await account.execute({ call: depositCall, signature });

      // Verify the deposit worked
      expect(await testContract.balances(account.target)).to.equal(ethers.parseEther('0.5'));

      // Now try to withdraw in a way that would allow reentrancy if not protected
      // In a real reentrancy attack, we would use a malicious contract, but here we're just testing
      // that the Account contract's reentrancy guard works as expected
      const withdrawCallData = testContract.interface.encodeFunctionData('withdraw', [ethers.parseEther('0.5')]);
      const withdrawCall = {
        target: await testContract.getAddress(),
        value: 0n,
        data: withdrawCallData,
      };

      challengeHash = await account.getChallenge(withdrawCall);
      webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      // Execute the withdrawal
      await account.execute({ call: withdrawCall, signature });

      // Verify the account got its ETH back
      const accountBalance = await ethers.provider.getBalance(account.target);
      expect(accountBalance).to.be.closeTo(
        ethers.parseEther('1.0'),
        ethers.parseEther('0.01'), // Allow small deviation for gas costs
      );

      // Verify withdraw was successful and the balance is now 0
      expect(await testContract.balances(account.target)).to.equal(0);
    });

    it('should prevent unauthorized admin operations', async function () {
      const { accountRegistry, adminKeypair, userKeypair } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Add user as an EXECUTOR (non-admin)
      const tx = await accountRegistry.requestAddKey(
        account.target,
        userKeypair.publicKey,
        1, // Role.EXECUTOR
      );

      // Get the request ID from the emitted event
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Approve the key request as admin
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        operationData,
        nonce: 0,
        signature: '0x',
      };

      // Sign the admin action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Approve the key request
      await account.approveKeyRequest(requestId, adminAction);

      // Now try to perform an admin operation with the EXECUTOR key
      // Try to pause the account
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const unauthorizedAdminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT
        operationData: pauseData,
        nonce: 1, // Next nonce
        signature: '0x',
      };

      // Sign with non-admin key
      const unauthorizedChallengeHash = await account.getAdminChallenge(unauthorizedAdminAction);
      unauthorizedAdminAction.signature = encodeChallenge(
        userKeypair.publicKey,
        signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(unauthorizedChallengeHash)),
      );

      // The operation should be rejected because the key is not an admin
      await expect(account.pauseAccount(pauseUntil, unauthorizedAdminAction)).to.be.revertedWithCustomError(
        account,
        'InvalidAdminSignature',
      );
    });

    it('should handle key rotation securely', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      // Create a new account with an initial admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Generate a new admin key to rotate to
      const newAdminKeypair = generateTestKeypair();

      // Request to add the new admin key
      const tx = await accountRegistry.requestAddKey(
        account.target,
        newAdminKeypair.publicKey,
        2, // Role.ADMIN
      );

      // Get the request ID from the emitted event
      const receipt = await tx.wait();
      const keyRequestedEvents = receipt?.logs
        .map((log) => {
          try {
            return account.interface.parseLog({ topics: log.topics, data: log.data });
          } catch (e) {
            return null;
          }
        })
        .filter((event): event is NonNullable<typeof event> => event !== null && event.name === 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      // Approve the key request with current admin
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        operationData,
        nonce: 0,
        signature: '0x',
      };

      // Sign the admin action
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      // Approve the key request
      await account.approveKeyRequest(requestId, adminAction);

      // Verify both keys are now admin
      expect(await account.getAdminKeyCount()).to.equal(2);

      // Now remove the original admin key using the new admin key
      const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['tuple(bytes32 x, bytes32 y)'],
        [[adminKeypair.publicKey.x, adminKeypair.publicKey.y]],
      );

      const removeKeyAction = {
        operation: 2, // AdminOperation.REMOVE_KEY
        operationData: removeKeyData,
        nonce: 1, // Next nonce
        signature: '0x',
      };

      // Sign with new admin key
      const removeKeyChallengeHash = await account.getAdminChallenge(removeKeyAction);
      removeKeyAction.signature = encodeChallenge(
        newAdminKeypair.publicKey,
        signWebAuthnChallenge(newAdminKeypair.keyPair.privateKey, ethers.getBytes(removeKeyChallengeHash)),
      );

      // Remove the original key
      await account.removeKey(adminKeypair.publicKey, removeKeyAction);

      // Verify only one admin key remains
      expect(await account.getAdminKeyCount()).to.equal(1);

      // Verify the old key can no longer perform admin actions
      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const oldKeyAdminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT
        operationData: pauseData,
        nonce: 2, // Next nonce
        signature: '0x',
      };

      // Sign with old admin key that was removed
      const oldKeyChallengeHash = await account.getAdminChallenge(oldKeyAdminAction);
      oldKeyAdminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(oldKeyChallengeHash)),
      );

      // The operation should be rejected because the key is no longer an admin
      await expect(account.pauseAccount(pauseUntil, oldKeyAdminAction)).to.be.revertedWithCustomError(
        account,
        'InvalidAdminSignature',
      );

      // But the new key should be able to perform admin actions
      const newKeyAdminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT
        operationData: pauseData,
        nonce: 2, // Next nonce
        signature: '0x',
      };

      // Sign with new admin key
      const newKeyChallengeHash = await account.getAdminChallenge(newKeyAdminAction);
      newKeyAdminAction.signature = encodeChallenge(
        newAdminKeypair.publicKey,
        signWebAuthnChallenge(newAdminKeypair.keyPair.privateKey, ethers.getBytes(newKeyChallengeHash)),
      );

      // This should succeed
      await account.pauseAccount(pauseUntil, newKeyAdminAction);

      // Confirm account is paused
      const [isPaused] = await account.isPaused();
      expect(isPaused).to.be.true;
    });

    it('should validate signatures correctly under different scenarios', async function () {
      const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

      // Create a new account with the admin key
      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      // Basic signature validation
      const callData = testContract.interface.encodeFunctionData('setValue', [123]);
      const call = {
        target: await testContract.getAddress(),
        value: 0n,
        data: callData,
      };

      // Get challenge hash and sign with admin key
      const challengeHash = await account.getChallenge(call);
      const webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      // Valid signature should work
      await account.execute({ call, signature });

      // Verify the value was set correctly
      expect(await testContract.value()).to.equal(123);

      // Tampered call data should fail
      const tamperedCall = {
        target: await testContract.getAddress(),
        value: 0n,
        data: testContract.interface.encodeFunctionData('setValue', [999]), // Different value
      };

      // The signature won't match the tampered call data
      await expect(account.execute({ call: tamperedCall, signature })).to.be.revertedWithCustomError(
        account,
        'InvalidExecutorSignature',
      );

      // Replay attack should fail - nonce has increased
      await expect(account.execute({ call, signature })).to.be.revertedWithCustomError(
        account,
        'InvalidExecutorSignature',
      );

      // ERC1271 compatibility test
      const messageHash = ethers.id('Test message');
      const webAuthnSig = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(messageHash));
      const erc1271Signature = encodeChallenge(adminKeypair.publicKey, webAuthnSig);

      // This should return the ERC1271 magic value (0x1626ba7e)
      const result = await account.isValidSignature(messageHash, erc1271Signature);
      expect(result).to.equal('0x1626ba7e');

      // Wrong signer should fail
      const wrongSignerSig = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(messageHash));
      const wrongErc1271Signature = encodeChallenge(userKeypair.publicKey, wrongSignerSig);

      const wrongResult = await account.isValidSignature(messageHash, wrongErc1271Signature);
      expect(wrongResult).to.equal('0xffffffff');
    });
  });
});
