import { encodeChallenge } from '@appliedblockchain/giano-common';
import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';
import type { Account, AccountRegistry } from '../typechain-types';
import type { HexifiedPublicKey } from './helpers/testSetup';
import { deployContracts } from './helpers/testSetup';
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
