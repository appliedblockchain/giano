import { encodeChallenge } from '@appliedblockchain/giano-common';
import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';
import type { Account, AccountRegistry } from '../typechain-types';
import type { HexifiedPublicKey, KeyPair } from './helpers/testSetup';
import { deployContracts, generateTestKeypair } from './helpers/testSetup';
import { extractEvents, signWebAuthnChallenge } from './utils';

/**
 * Helper functions for common test operations
 */

/**
 * Get an admin action with signature for specified operation
 * @param account Account contract
 * @param adminKeypair Admin keypair to sign with
 * @param operation Admin operation code
 * @param operationData ABI encoded operation data
 * @returns Signed admin action object
 */
async function getSignedAdminAction(account: Account, adminKeypair: KeyPair, operation: number, operationData: string) {
  const adminNonce = await account.getAdminNonce();

  const adminAction = {
    operation,
    operationData,
    nonce: Number(adminNonce),
    signature: '0x', // Will be set below
  };

  const challengeHash = await account.getAdminChallenge(adminAction);
  adminAction.signature = encodeChallenge(
    adminKeypair.publicKey,
    signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
  );

  return adminAction;
}

async function createAndGetAccount(adminKeypair: KeyPair, accountRegistry: AccountRegistry): Promise<Account> {
  const tx = await accountRegistry.createUser(adminKeypair.publicKey);
  const receipt = await tx.wait();

  const userCreatedEvents = await extractEvents(receipt, accountRegistry, 'UserCreated');

  if (!userCreatedEvents?.length || !userCreatedEvents[0].args) {
    throw new Error('UserCreated event not found');
  }

  const accountAddress = userCreatedEvents[0].args.account;
  return await ethers.getContractAt('Account', accountAddress);
}

/**
 * Request a key to be added to an account
 * @param account Account contract instance
 * @param accountRegistry Registry contract instance
 * @param keyToAdd Public key to add
 * @param role Role to assign to the key
 * @returns The request ID
 */
async function requestAddKey(
  account: Account,
  accountRegistry: AccountRegistry,
  keyToAdd: HexifiedPublicKey,
  role: number,
): Promise<string> {
  const accountAddress = await account.getAddress();
  const tx = await accountRegistry.requestAddKey(accountAddress, keyToAdd, role);
  const receipt = await tx.wait();

  const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');
  if (!keyRequestedEvents?.length || !keyRequestedEvents[0].args) {
    throw new Error('KeyRequested event not found');
  }

  return keyRequestedEvents[0].args.requestId;
}

/**
 * Approve a key request
 * @param account Account contract instance
 * @param adminKeypair Admin keypair to sign with
 * @param requestId ID of the key request to approve
 */
async function approveKeyRequest(account: Account, adminKeypair: KeyPair, requestId: string): Promise<void> {
  const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
  const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData); // 0 = APPROVE_KEY_REQUEST
  await account.approveKeyRequest(requestId, adminAction);
}

/**
 * Creates a signedAction for pausing an account
 * @param account Account contract instance
 * @param adminKeypair Admin keypair to sign with
 * @param pauseUntil Timestamp until when the account should be paused
 * @returns Signed admin action for pausing
 */
async function getPauseAccountAction(account: Account, adminKeypair: KeyPair, pauseUntil: number) {
  const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
  return await getSignedAdminAction(account, adminKeypair, 4, pauseData); // 4 = PAUSE_ACCOUNT
}

/**
 * Creates a signedAction for unpausing an account
 * @param account Account contract instance
 * @param adminKeypair Admin keypair to sign with
 * @returns Signed admin action for unpausing
 */
async function getUnpauseAccountAction(account: Account, adminKeypair: KeyPair) {
  return await getSignedAdminAction(account, adminKeypair, 5, '0x'); // 5 = UNPAUSE_ACCOUNT, no data needed
}

/**
 * Sign a call to be executed by the account
 * @param account Account contract instance
 * @param keypair Keypair to sign with
 * @param call The call object to sign
 * @returns Signed call object ready for execution
 */
async function signCall(account: Account, keypair: KeyPair, call: { target: string; value: bigint; data: string }) {
  const challengeHash = await account.getChallenge(call);
  const webAuthnSignature = signWebAuthnChallenge(keypair.keyPair.privateKey, ethers.getBytes(challengeHash));
  const signature = encodeChallenge(keypair.publicKey, webAuthnSignature);
  return { call, signature };
}

/**
 * Sign a batch of calls to be executed by the account
 * @param account Account contract instance
 * @param keypair Keypair to sign with
 * @param calls The array of call objects to sign
 * @returns Signed batch call object ready for execution
 */
async function signBatchCall(
  account: Account,
  keypair: KeyPair,
  calls: { target: string; value: bigint; data: string }[],
) {
  const challengeHash = await account.getBatchChallenge(calls);
  const webAuthnSignature = signWebAuthnChallenge(keypair.keyPair.privateKey, ethers.getBytes(challengeHash));
  const signature = encodeChallenge(keypair.publicKey, webAuthnSignature);
  return { calls, signature };
}

describe('Account Contract', function () {
  describe('Initialization', function () {
    it('should initialize with correct registry address', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      expect(await account.registry()).to.equal(await accountRegistry.getAddress());
    });

    it('should set up the initial admin key correctly', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        expect(keyRequestedEvents?.length).to.be.greaterThan(0);
        expect(keyRequestedEvents?.[0].args.publicKey.x).to.equal(executorKeypair.publicKey.x);
        expect(keyRequestedEvents?.[0].args.publicKey.y).to.equal(executorKeypair.publicKey.y);
        expect(keyRequestedEvents?.[0].args.requestedRole).to.equal(1); // Role.EXECUTOR = 1
      });

      it('should emit KeyRequested event with correct parameters', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        await expect(
          accountRegistry.requestAddKey(
            accountAddress,
            executorKeypair.publicKey,
            1, // Role.EXECUTOR = 1
          ),
        )
          .to.emit(account, 'KeyRequested')
          .withArgs(
            (requestId: string) => ethers.isHexString(requestId, 32), // 32 bytes
            (publicKey: any) => {
              return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
            },
            1, // Role.EXECUTOR = 1
          );
      });

      it('should reject requests for keys that already exist', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

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

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        await expect(
          account.connect(user1).requestAddKey(
            executorKeypair.publicKey,
            1, // Role.EXECUTOR = 1
          ),
        ).to.be.revertedWithCustomError(account, 'OnlyRegistryCanAddKeys');
      });

      it('should generate unique request IDs', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

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

        const receipt1 = await tx1.wait();
        const receipt2 = await tx2.wait();

        const keyRequestedEvents1 = await extractEvents(receipt1, account, 'KeyRequested');

        const keyRequestedEvents2 = await extractEvents(receipt2, account, 'KeyRequested');

        expect(keyRequestedEvents1?.length).to.be.greaterThan(0);
        expect(keyRequestedEvents2?.length).to.be.greaterThan(0);

        const requestId1 = keyRequestedEvents1?.[0].args.requestId;
        const requestId2 = keyRequestedEvents2?.[0].args.requestId;

        expect(requestId1).to.not.equal(requestId2);
      });
    });

    describe('Key Request Approval', function () {
      it('should add a key when request is approved by admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const requestId = await requestAddKey(account, accountRegistry, executorKeypair.publicKey, 1); // Role.EXECUTOR = 1

        await approveKeyRequest(account, adminKeypair, requestId);

        const keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1
      });

      it('should increment admin key count when adding admin key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const initialAdminKeyCount = await account.getAdminKeyCount();
        expect(initialAdminKeyCount).to.equal(1);

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await account.approveKeyRequest(requestId, adminAction);

        const newAdminKeyCount = await account.getAdminKeyCount();
        expect(newAdminKeyCount).to.equal(2);
      });

      it('should emit KeyRequestApproved and KeyAdded events', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await expect(account.approveKeyRequest(requestId, adminAction))
          .to.emit(account, 'KeyRequestApproved')
          .withArgs(
            requestId,
            (publicKey: any) => {
              return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
            },
            1
          ) // Role.EXECUTOR = 1
          .and.to.emit(account, 'KeyAdded')
          .withArgs(
            (publicKey: any) => {
              return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
            },
            1
          ); // Role.EXECUTOR = 1
      });

      it('should remove the key request after approval', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await account.approveKeyRequest(requestId, adminAction);

        const newAdminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await expect(account.approveKeyRequest(requestId, newAdminAction))
          .to.be.revertedWithCustomError(account, 'RequestDoesNotExist')
          .withArgs(requestId);
      });

      it('should notify registry about the added key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await expect(account.approveKeyRequest(requestId, adminAction)).to.emit(accountRegistry, 'KeyLinked');

        const [isLinked, linkedAccount] = await accountRegistry.isKeyLinked(executorKeypair.publicKey);
        expect(isLinked).to.be.true;
        expect(linkedAccount).to.equal(accountAddress);
      });

      it('should only allow approved requests with valid signatures', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

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

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

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

        const receipt1 = await tx1.wait();
        const keyRequestedEvents1 = await extractEvents(receipt1, account, 'KeyRequested');

        const receipt2 = await tx2.wait();
        const keyRequestedEvents2 = await extractEvents(receipt2, account, 'KeyRequested');

        const requestId1 = keyRequestedEvents1?.[0].args.requestId;
        const requestId2 = keyRequestedEvents2?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId2]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await expect(account.approveKeyRequest(requestId1, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidOperationData',
        );
      });
    });

    describe('Key Request Rejection', function () {
      it('should reject a key request when called by admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 1, operationData);

        await account.rejectKeyRequest(requestId, adminAction);

        const keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(0); // Role.NONE = 0
      });

      it('should emit KeyRequestRejected event', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 1, operationData);

        await expect(account.rejectKeyRequest(requestId, adminAction))
          .to.emit(account, 'KeyRequestRejected')
          .withArgs(requestId);
      });

      it('should remove the key request after rejection', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 1, operationData);

        await account.rejectKeyRequest(requestId, adminAction);

        const newOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const newAdminAction = await getSignedAdminAction(account, adminKeypair, 1, newOperationData);

        await expect(account.rejectKeyRequest(requestId, newAdminAction))
          .to.be.revertedWithCustomError(account, 'RequestDoesNotExist')
          .withArgs(requestId);
      });

      it('should fail when request does not exist', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const nonExistentRequestId = ethers.keccak256(ethers.toUtf8Bytes('non-existent-request'));

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [nonExistentRequestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 1, operationData);

        await expect(account.rejectKeyRequest(nonExistentRequestId, adminAction))
          .to.be.revertedWithCustomError(account, 'RequestDoesNotExist')
          .withArgs(nonExistentRequestId);
      });

      it('should only allow rejection with valid admin signature', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 1, operationData);

        const challengeHash = await account.getAdminChallenge(adminAction);

        adminAction.signature = encodeChallenge(
          userKeypair.publicKey,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.rejectKeyRequest(requestId, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidAdminSignature',
        );
      });
    });

    describe('Key Removal', function () {
      it('should remove an existing key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        let keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 2, operationData);

        await account.removeKey(executorKeypair.publicKey, adminAction);

        keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(0); // Role.NONE = 0
      });

      it('should fail to remove a non-existent key', async function () {
        const { accountRegistry, adminKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[userKeypair.publicKey.x, userKeypair.publicKey.y]],
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 2, operationData);

        await expect(account.removeKey(userKeypair.publicKey, adminAction))
          .to.be.revertedWithCustomError(account, 'KeyDoesNotExist')
          .withArgs(userKeypair.publicKey.x, userKeypair.publicKey.y);
      });

      it('should decrement admin key count when removing admin key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        expect(await account.getAdminKeyCount()).to.equal(2);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 2, operationData);

        await account.removeKey(executorKeypair.publicKey, adminAction);

        expect(await account.getAdminKeyCount()).to.equal(1);
      });

      it('should prevent removing the last admin key', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        expect(await account.getAdminKeyCount()).to.equal(1);

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

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const removeAction = await getSignedAdminAction(account, adminKeypair, 2, operationData);

        await expect(account.removeKey(executorKeypair.publicKey, removeAction))
          .to.emit(account, 'KeyRemoved')
          .withArgs((publicKey: any) => {
            return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
          });
      });

      it('should notify registry about the removed key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        const [isLinked, linkedAccount] = await accountRegistry.isKeyLinked(executorKeypair.publicKey);
        expect(isLinked).to.be.true;
        expect(linkedAccount).to.equal(accountAddress);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const removeAction = await getSignedAdminAction(account, adminKeypair, 2, operationData);

        await expect(account.removeKey(executorKeypair.publicKey, removeAction))
          .to.emit(accountRegistry, 'KeyUnlinked');

        const [isStillLinked, _] = await accountRegistry.isKeyLinked(executorKeypair.publicKey);
        expect(isStillLinked).to.be.false;
      });

      it('should only allow removal with valid admin signature', async function () {
        const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y]],
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 2, operationData);

        const challengeHash = await account.getAdminChallenge(adminAction);

        adminAction.signature = encodeChallenge(
          userKeypair.publicKey,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.removeKey(executorKeypair.publicKey, adminAction)).to.be.revertedWithCustomError(
          account,
          'InvalidAdminSignature',
        );
      });
    });

    describe('Key Role Changes', function () {
      it('should change role of an existing key', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        let keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 3, operationData);

        await account.changeKeyRole(executorKeypair.publicKey, 2, adminAction); // Role.ADMIN = 2

        keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
        expect(keyInfo.role).to.equal(2); // Role.ADMIN = 2
      });

      it('should fail to change role of a non-existent key', async function () {
        const { accountRegistry, adminKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[userKeypair.publicKey.x, userKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 3, operationData);

        await expect(account.changeKeyRole(userKeypair.publicKey, 2, adminAction))
          .to.be.revertedWithCustomError(account, 'KeyDoesNotExist')
          .withArgs(userKeypair.publicKey.x, userKeypair.publicKey.y);
      });

      it('should increment admin key count when upgrading to admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const initialAdminKeyCount = await account.getAdminKeyCount();
        expect(initialAdminKeyCount).to.equal(1);

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        expect(await account.getAdminKeyCount()).to.equal(1);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 3, operationData);

        await account.changeKeyRole(executorKeypair.publicKey, 2, adminAction); // Role.ADMIN = 2

        expect(await account.getAdminKeyCount()).to.equal(2);
      });

      it('should decrement admin key count when downgrading from admin', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        expect(await account.getAdminKeyCount()).to.equal(2);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 1], // Role.EXECUTOR = 1
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 3, operationData);

        await account.changeKeyRole(executorKeypair.publicKey, 1, adminAction); // Role.EXECUTOR = 1

        expect(await account.getAdminKeyCount()).to.equal(1);
      });

      it('should prevent removing the last admin key', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        expect(await account.getAdminKeyCount()).to.equal(1);

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

      it('should prevent downgrading the last admin key', async function () {
        const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        expect(await account.getAdminKeyCount()).to.equal(1);

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

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 2], // Role.ADMIN = 2
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 3, operationData);

        await expect(account.changeKeyRole(executorKeypair.publicKey, 2, adminAction))
          .to.emit(account, 'KeyRoleChanged')
          .withArgs((publicKey: any) => {
            return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
          }, 2); // Role.ADMIN = 2
      });

      it('should validate operation data matches key and new role', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const approveOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const approveAction = await getSignedAdminAction(account, adminKeypair, 0, approveOperationData);

        await account.approveKeyRequest(requestId, approveAction);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[executorKeypair.publicKey.x, executorKeypair.publicKey.y], 1], // Role.EXECUTOR = 1 (incorrect)
        );

        const adminAction = await getSignedAdminAction(account, adminKeypair, 3, operationData);

        await expect(account.changeKeyRole(executorKeypair.publicKey, 2, adminAction)) // Role.ADMIN = 2
          .to.be.revertedWithCustomError(account, 'InvalidOperationData');
      });
    });
  });

  describe('Transaction Execution', function () {
    describe('Single Transactions', function () {
      it('should execute a transaction with valid signature', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const signedCall = await signCall(account, adminKeypair, call);

        await account.execute(signedCall);

        expect(await testContract.value()).to.equal(42);
        expect(await testContract.lastCaller()).to.equal(await account.getAddress());
      });

      it('should reject execution with invalid signature', async function () {
        const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
        const signature = encodeChallenge(userKeypair.publicKey, webAuthnSignature);

        await expect(account.execute({ call, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should increment nonce after successful execution', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        expect(await account.getNonce()).to.equal(0);

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

        expect(await account.getNonce()).to.equal(1);
      });

      it('should emit Executed event', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        await expect(account.execute({ call, signature }))
          .to.emit(account, 'Executed')
          .withArgs(0, await testContract.getAddress(), 0, callData);
      });

      it('should pass correct value to target contract', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        await ethers.provider.send('hardhat_setBalance', [
          await account.getAddress(),
          '0x1000000000000000000', // 1 ETH
        ]);

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

        await account.execute({ call, signature });

        expect(await testContract.balances(await account.getAddress())).to.equal(ethToSend);
      });

      it('should forward revert reasons from target contracts', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        await expect(account.execute({ call, signature })).to.be.revertedWith(errorMessage);
      });

      it('should prevent execution when paused', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
        const adminAction = await getSignedAdminAction(account, adminKeypair, 4, pauseData);

        await account.pauseAccount(pauseUntil, adminAction);

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

        await expect(account.execute({ call, signature: txSignature }))
          .to.be.revertedWithCustomError(account, 'AccountIsPaused')
          .withArgs(pauseUntil);
      });
    });

    describe('Batch Transactions', function () {
      it('should execute multiple transactions in one call', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        const signedBatch = await signBatchCall(account, adminKeypair, calls);

        await account.executeBatch(signedBatch);

        expect(await testContract.value()).to.equal(42);
        expect(await testContract.message()).to.equal('Hello from batch');
        expect(await testContract.lastCaller()).to.equal(await account.getAddress());
      });

      it('should validate batch challenge correctly', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        await expect(account.executeBatch({ calls: modifiedCalls, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should reject with invalid signature', async function () {
        const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
        const signature = encodeChallenge(userKeypair.publicKey, webAuthnSignature);

        await expect(account.executeBatch({ calls, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should increment nonce only once for the batch', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        expect(await account.getNonce()).to.equal(0);

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

        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        await account.executeBatch({ calls, signature });

        expect(await account.getNonce()).to.equal(1);
      });

      it('should emit one Executed event for the batch', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        const tx = await account.executeBatch({ calls, signature });
        const receipt = await tx.wait();
        expect(receipt).to.not.be.null;

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

        expect(executedEvents.length).to.equal(1);
        const executedEvent = executedEvents[0];

        expect(executedEvent.args.nonce).to.equal(0);
        expect(executedEvent.args.target).to.equal(ethers.ZeroAddress);
        expect(executedEvent.args.value).to.equal(0);

        expect(executedEvent.args.data).to.not.be.null;
      });

      it('should revert entire batch if one call fails', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

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

        const challengeHash = await account.getBatchChallenge(calls);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        await expect(account.executeBatch({ calls, signature })).to.be.revertedWith('Intentional failure');

        expect(await testContract.value()).to.equal(0); // Not 42
      });

      it('should prevent execution when paused', async function () {
        const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeypair, accountRegistry);

        const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
        const adminAction = await getSignedAdminAction(account, adminKeypair, 4, pauseData);

        await account.pauseAccount(pauseUntil, adminAction);

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

        const batchChallengeHash = await account.getBatchChallenge(calls);
        const batchSignature = encodeChallenge(
          adminKeypair.publicKey,
          signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(batchChallengeHash)),
        );

        await expect(account.executeBatch({ calls, signature: batchSignature }))
          .to.be.revertedWithCustomError(account, 'AccountIsPaused')
          .withArgs(pauseUntil);
      });
    });
  });

  describe('Admin Operations', function () {
    it('should validate admin signatures correctly', async function () {
        const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const receipt = await tx.wait();
      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

      const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

      await expect(account.approveKeyRequest(requestId, adminAction)).to.not.be.reverted;

      const keyInfo = await account.getKeyInfo(executorKeypair.publicKey);
      expect(keyInfo.role).to.equal(1); // Role.EXECUTOR = 1
    });

    it('should increment admin nonce after operations', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      const initialAdminNonce = await account.getAdminNonce();
      expect(initialAdminNonce).to.equal(0);

      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const receipt = await tx.wait();
      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

      await account.approveKeyRequest(requestId, adminAction);

      const newAdminNonce = await account.getAdminNonce();
      expect(newAdminNonce).to.equal(1);

      const tx2 = await accountRegistry.requestAddKey(
        accountAddress,
        { x: ethers.hexlify(ethers.randomBytes(32)), y: ethers.hexlify(ethers.randomBytes(32)) },
        1, // Role.EXECUTOR = 1
      );

      const receipt2 = await tx2.wait();
      const keyRequestedEvents2 = await extractEvents(receipt2, account, 'KeyRequested');

      const requestId2 = keyRequestedEvents2?.[0].args.requestId;

      const operationData2 = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId2]);
      const adminAction2 = await getSignedAdminAction(account, adminKeypair, 0, operationData2);

      await account.approveKeyRequest(requestId2, adminAction2);

      const finalAdminNonce = await account.getAdminNonce();
      expect(finalAdminNonce).to.equal(2);
    });

    it('should emit AdminActionExecuted event', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const receipt = await tx.wait();
      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

      const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

      await expect(account.approveKeyRequest(requestId, adminAction))
        .to.emit(account, 'AdminActionExecuted')
        .withArgs(0, adminNonce); // AdminOperation.APPROVE_KEY_REQUEST = 0
    });

    it('should reject operations with invalid nonce', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const requestId = await requestAddKey(account, accountRegistry, executorKeypair.publicKey, 1);

      const adminNonce = await account.getAdminNonce();

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST = 0
        operationData,
        nonce: Number(adminNonce) + 1, // Incorrect nonce
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.approveKeyRequest(requestId, adminAction))
        .to.be.revertedWithCustomError(account, 'InvalidNonce')
        .withArgs(adminNonce, Number(adminNonce) + 1);
    });

    it('should reject operations with wrong operation type', async function () {
      const { accountRegistry, adminKeypair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const receipt = await tx.wait();
      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = await getSignedAdminAction(account, adminKeypair, 1, operationData);

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.approveKeyRequest(requestId, adminAction))
        .to.be.revertedWithCustomError(account, 'InvalidOperation')
        .withArgs(0, 1); // Expected APPROVE_KEY_REQUEST=0, got REJECT_KEY_REQUEST=1
    });

    it('should reject operations with invalid signature', async function () {
      const { accountRegistry, adminKeypair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);
      const accountAddress = await account.getAddress();

      const tx = await accountRegistry.requestAddKey(
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const receipt = await tx.wait();
      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      const requestId = keyRequestedEvents?.[0].args.requestId;

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        userKeypair.publicKey, // Non-admin key
        signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.approveKeyRequest(requestId, adminAction)).to.be.revertedWithCustomError(
        account,
        'InvalidAdminSignature',
      );
    });
  });

  describe('Pause Functionality', function () {
    it('should allow admin to pause the account', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600;

      const adminAction = await getPauseAccountAction(account, adminKeypair, pauseUntil);

      await expect(account.pauseAccount(pauseUntil, adminAction)).to.not.be.reverted;

      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.true;
      expect(pausedUntilTime).to.equal(pauseUntil);
    });

    it('should emit AccountPaused event with correct timestamp', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 7200; // 2 hours from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.pauseAccount(pauseUntil, adminAction))
        .to.emit(account, 'AccountPaused')
        .withArgs(pauseUntil);
    });

    it('should prevent transaction execution while paused', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await account.pauseAccount(pauseUntil, adminAction);

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

      await expect(account.execute({ call, signature: txSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(pauseUntil);

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

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [0]);

      const adminNonce = await account.getAdminNonce();
      const adminAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await account.pauseAccount(0, adminAction);

      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.true;
      expect(pausedUntilTime).to.equal(ethers.MaxUint256);

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

      await expect(account.execute({ call, signature: txSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(ethers.MaxUint256);
    });

    it('should allow admin to unpause the account', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      await account.pauseAccount(pauseUntil, pauseAction);

      const unpauseAction = await getUnpauseAccountAction(account, adminKeypair);

      await expect(account.unpauseAccount(unpauseAction)).to.not.be.reverted;

      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntilTime).to.equal(0);
    });

    it('should emit AccountUnpaused event', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      let adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      await account.pauseAccount(pauseUntil, pauseAction);

      adminNonce = await account.getAdminNonce();
      const unpauseAction = {
        operation: 5, // AdminOperation.UNPAUSE_ACCOUNT = 5
        operationData: '0x', // No data needed for unpause
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      await expect(account.unpauseAccount(unpauseAction)).to.emit(account, 'AccountUnpaused');
    });

    it('should allow transaction execution after unpausing', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      await account.pauseAccount(pauseUntil, pauseAction);

      const unpauseAction = await getUnpauseAccountAction(account, adminKeypair);

      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      await account.unpauseAccount(unpauseAction);

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

      await account.execute({ call, signature: txSignature });

      expect(await testContract.value()).to.equal(42);
    });

    it('should report pause status correctly', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      let [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntilTime).to.equal(0);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const adminNonce = await account.getAdminNonce();
      const pauseAction = {
        operation: 4, // AdminOperation.PAUSE_ACCOUNT = 4
        operationData: pauseData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const pauseChallengeHash = await account.getAdminChallenge(pauseAction);
      pauseAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      await account.pauseAccount(pauseUntil, pauseAction);

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
        const fixture = await loadFixture(deployContracts);
        adminKeypair = fixture.adminKeypair;

        executorKeypair = generateTestKeypair();
        nonAuthorizedKeypair = generateTestKeypair();

        account = await createAndGetAccount(adminKeypair, fixture.accountRegistry);

        const accountAddress = await account.getAddress();

        const tx = await fixture.accountRegistry.requestAddKey(
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

        const requestId = keyRequestedEvents?.[0].args.requestId;

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);

        const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

        await account.approveKeyRequest(requestId, adminAction);
      });

      it('should return the ERC1271 magic value for a valid signature', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        const webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(messageHash));

        const encodedSignature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0x1626ba7e');
      });

      it('should return the magic value for a valid executor signature', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello from executor!'));

        const webAuthnSignature = signWebAuthnChallenge(
          executorKeypair.keyPair.privateKey,
          ethers.getBytes(messageHash),
        );

        const encodedSignature = encodeChallenge(executorKeypair.publicKey, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0x1626ba7e');
      });

      it('should not return the magic value for an invalid signature', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        const differentMessageHash = ethers.keccak256(ethers.toUtf8Bytes('Different message!'));

        const webAuthnSignature = signWebAuthnChallenge(
          adminKeypair.keyPair.privateKey,
          ethers.getBytes(differentMessageHash),
        );

        const encodedSignature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0xffffffff');
      });

      it('should not return the magic value for a signature from unauthorized key', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        const webAuthnSignature = signWebAuthnChallenge(
          nonAuthorizedKeypair.keyPair.privateKey,
          ethers.getBytes(messageHash),
        );

        const encodedSignature = encodeChallenge(nonAuthorizedKeypair.publicKey, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0xffffffff');
      });
    });

    describe('ERC721/ERC1155 Receiver', function () {
      let account: Account;
      let adminKeypair: KeyPair;
      let accountRegistry: AccountRegistry;

      beforeEach(async function () {
        const fixture = await loadFixture(deployContracts);
        adminKeypair = fixture.adminKeypair;
        accountRegistry = fixture.accountRegistry;
        account = await createAndGetAccount(adminKeypair, accountRegistry);
      });

      it('should implement onERC721Received correctly', async function () {
        const ERC721ReceiverSelector = '0x150b7a02'; // bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))

        const result = await account.onERC721Received(ethers.ZeroAddress, ethers.ZeroAddress, 0, '0x');

        expect(result).to.equal(ERC721ReceiverSelector);
      });

      it('should implement onERC1155Received correctly', async function () {
        const ERC1155ReceivedSelector = '0xf23a6e61'; // bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))

        const result = await account.onERC1155Received(ethers.ZeroAddress, ethers.ZeroAddress, 0, 1, '0x');

        expect(result).to.equal(ERC1155ReceivedSelector);
      });

      it('should implement onERC1155BatchReceived correctly', async function () {
        const ERC1155BatchReceivedSelector = '0xbc197c81'; // bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))

        const result = await account.onERC1155BatchReceived(ethers.ZeroAddress, ethers.ZeroAddress, [], [], '0x');

        expect(result).to.equal(ERC1155BatchReceivedSelector);
      });

      it('should support relevant interfaces', async function () {
        const ERC721ReceiverInterfaceId = '0x150b7a02'; // IERC721Receiver
        const ERC1155ReceiverInterfaceId = '0x4e2312e0'; // IERC1155Receiver
        const ERC1271InterfaceId = '0x1626ba7e'; // IERC1271

        expect(await account.supportsInterface(ERC721ReceiverInterfaceId)).to.be.true;
        expect(await account.supportsInterface(ERC1155ReceiverInterfaceId)).to.be.true;
        expect(await account.supportsInterface(ERC1271InterfaceId)).to.be.true;

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
      const fixture = await loadFixture(deployContracts);
      adminKeypair = fixture.adminKeypair;
      accountRegistry = fixture.accountRegistry;
      account = await createAndGetAccount(adminKeypair, accountRegistry);
      userKeypair = generateTestKeypair();
    });

    it('should calculate challenge hash correctly for single calls', async function () {
      const call = {
        target: ethers.ZeroAddress,
        value: 0n,
        data: '0x',
        nonce: await account.getNonce(),
      };

      const expectedHash = ethers.keccak256(
        ethers.concat([
          ethers.zeroPadValue(ethers.hexlify(await account.getAddress()), 20),
          ethers.zeroPadValue(ethers.toBeHex(call.nonce), 32),
          ethers.zeroPadValue(ethers.hexlify(call.target), 20), // ZeroAddress is already a hex string
          ethers.zeroPadValue(ethers.toBeHex(call.value), 32),
          call.data || '0x',
        ]),
      );

      const challengeHash = await account.getChallenge(call);

      expect(challengeHash).to.equal(expectedHash);
    });

    it('should calculate challenge hash correctly for batch calls', async function () {
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

      const challengeHash = await account.getBatchChallenge(calls);

      expect(challengeHash).to.equal(expectedHash);
    });

    it('should calculate admin challenge hash correctly', async function () {
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

      const expectedHash = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'uint8', 'bytes', 'uint256'],
          [account.target, adminAction.operation, adminAction.operationData, adminAction.nonce],
        ),
      );

      const challengeHash = await account.getAdminChallenge(adminAction);

      expect(challengeHash).to.equal(expectedHash);
    });

    it('should return correct key info for existing key', async function () {
      const keyInfo = await account.getKeyInfo(adminKeypair.publicKey);

      expect(keyInfo.publicKey.x).to.equal(adminKeypair.publicKey.x);
      expect(keyInfo.publicKey.y).to.equal(adminKeypair.publicKey.y);
      expect(keyInfo.role).to.equal(2); // Role.ADMIN = 2
    });

    it('should return empty key info for non-existent key', async function () {
      const keyInfo = await account.getKeyInfo(userKeypair.publicKey);

      expect(keyInfo.role).to.equal(0); // Role.NONE = 0
    });

    it('should return correct admin nonce', async function () {
      const initialNonce = await account.getAdminNonce();
      expect(initialNonce).to.equal(0);

      const tx = await accountRegistry.requestAddKey(account.target, userKeypair.publicKey, 1); // Role.EXECUTOR = 1
      const receipt = await tx.wait();

      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      if (!keyRequestedEvents?.length) {
        throw new Error('KeyRequested event not found');
      }

      const requestId = keyRequestedEvents[0].args.requestId;

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        nonce: initialNonce,
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]),
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await account.approveKeyRequest(requestId, adminAction);

      const newNonce = await account.getAdminNonce();
      expect(newNonce).to.equal(1);
    });

    it('should return correct transaction nonce', async function () {
      const initialNonce = await account.getNonce();
      expect(initialNonce).to.equal(0);

      const call = {
        target: ethers.ZeroAddress,
        value: 0n,
        data: '0x',
        nonce: initialNonce,
      };

      const challengeHash = await account.getChallenge(call);
      const webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      await account.execute({ call, signature });

      const newNonce = await account.getNonce();
      expect(newNonce).to.equal(1);
    });

    it('should return correct admin key count', async function () {
      expect(await account.getAdminKeyCount()).to.equal(1);

      const tx = await accountRegistry.requestAddKey(account.target, userKeypair.publicKey, 1); // Role.EXECUTOR = 1
      const receipt = await tx.wait();

      const keyRequestedEvents = await extractEvents(receipt, account, 'KeyRequested');

      if (!keyRequestedEvents?.length) {
        throw new Error('KeyRequested event not found');
      }

      const requestId = keyRequestedEvents[0].args.requestId;

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_KEY_REQUEST
        nonce: await account.getAdminNonce(),
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]),
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await account.approveKeyRequest(requestId, adminAction);

      expect(await account.getAdminKeyCount()).to.equal(1);

      const changeKeyRoleAction = {
        operation: 3, // AdminOperation.CHANGE_KEY_ROLE = 3
        nonce: await account.getAdminNonce(),
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(bytes32 x, bytes32 y)', 'uint8'],
          [[userKeypair.publicKey.x, userKeypair.publicKey.y], 2], // Role.ADMIN = 2
        ),
        signature: '0x',
      };

      const challengeHash2 = await account.getAdminChallenge(changeKeyRoleAction);
      changeKeyRoleAction.signature = encodeChallenge(
        adminKeypair.publicKey,
        signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash2)),
      );

      await account.changeKeyRole(userKeypair.publicKey, 2, changeKeyRoleAction); // Role.ADMIN = 2

      expect(await account.getAdminKeyCount()).to.equal(2);
    });

    it('should check if account is paused correctly', async function () {
      const [isPausedInitial, untilInitial] = await account.isPaused();
      expect(isPausedInitial).to.be.false;
      expect(untilInitial).to.equal(0);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const adminAction = await getPauseAccountAction(account, adminKeypair, pauseUntil);

      await account.pauseAccount(pauseUntil, adminAction);

      const [isPausedAfter, untilAfter] = await account.isPaused();
      expect(isPausedAfter).to.be.true;
      expect(untilAfter).to.equal(pauseUntil);

      const unpauseAction = await getUnpauseAccountAction(account, adminKeypair);

      await account.unpauseAccount(unpauseAction);

      const [isPausedFinal, untilFinal] = await account.isPaused();
      expect(isPausedFinal).to.be.false;
      expect(untilFinal).to.equal(0);
    });
  });

  describe('Security Features', function () {
    it('should prevent reentrancy attacks', async function () {
      const { accountRegistry, adminKeypair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      await ethers.provider.send('hardhat_setBalance', [account.target, ethers.toBeHex(ethers.parseEther('1.0'))]);

      const depositCallData = testContract.interface.encodeFunctionData('deposit');
      const depositCall = {
        target: await testContract.getAddress(),
        value: ethers.parseEther('0.5'),
        data: depositCallData,
      };

      let challengeHash = await account.getChallenge(depositCall);
      let webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      let signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      await account.execute({ call: depositCall, signature });

      expect(await testContract.balances(account.target)).to.equal(ethers.parseEther('0.5'));

      const withdrawCallData = testContract.interface.encodeFunctionData('withdraw', [ethers.parseEther('0.5')]);
      const withdrawCall = {
        target: await testContract.getAddress(),
        value: 0n,
        data: withdrawCallData,
      };

      challengeHash = await account.getChallenge(withdrawCall);
      webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      await account.execute({ call: withdrawCall, signature });

      const accountBalance = await ethers.provider.getBalance(account.target);
      expect(accountBalance).to.be.closeTo(
        ethers.parseEther('1.0'),
        ethers.parseEther('0.01'), // Allow small deviation for gas costs
      );

      expect(await testContract.balances(account.target)).to.equal(0);
    });

    it('should prevent unauthorized admin operations', async function () {
      const { accountRegistry, adminKeypair, userKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const tx = await accountRegistry.requestAddKey(
        account.target,
        userKeypair.publicKey,
        1, // Role.EXECUTOR
      );

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

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

      await account.approveKeyRequest(requestId, adminAction);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const unauthorizedAdminAction = await getSignedAdminAction(account, userKeypair, 4, pauseData);

      await expect(account.pauseAccount(pauseUntil, unauthorizedAdminAction)).to.be.revertedWithCustomError(
        account,
        'InvalidAdminSignature',
      );
    });

    it('should handle key rotation securely', async function () {
      const { accountRegistry, adminKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const newAdminKeypair = generateTestKeypair();

      const tx = await accountRegistry.requestAddKey(
        account.target,
        newAdminKeypair.publicKey,
        2, // Role.ADMIN
      );

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

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [requestId]);
      const adminAction = await getSignedAdminAction(account, adminKeypair, 0, operationData);

      await account.approveKeyRequest(requestId, adminAction);

      expect(await account.getAdminKeyCount()).to.equal(2);

      const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['tuple(bytes32 x, bytes32 y)'],
        [[adminKeypair.publicKey.x, adminKeypair.publicKey.y]],
      );

      const removeKeyAction = await getSignedAdminAction(account, newAdminKeypair, 2, removeKeyData);

      await account.removeKey(adminKeypair.publicKey, removeKeyAction);

      expect(await account.getAdminKeyCount()).to.equal(1);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
      const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);

      const oldKeyAdminAction = await getSignedAdminAction(account, adminKeypair, 4, pauseData);

      await expect(account.pauseAccount(pauseUntil, oldKeyAdminAction)).to.be.revertedWithCustomError(
        account,
        'InvalidAdminSignature',
      );

      const newKeyAdminAction = await getSignedAdminAction(account, newAdminKeypair, 4, pauseData);

      await account.pauseAccount(pauseUntil, newKeyAdminAction);

      const [isPaused] = await account.isPaused();
      expect(isPaused).to.be.true;
    });

    it('should validate signatures correctly under different scenarios', async function () {
      const { accountRegistry, adminKeypair, userKeypair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeypair, accountRegistry);

      const callData = testContract.interface.encodeFunctionData('setValue', [123]);
      const call = {
        target: await testContract.getAddress(),
        value: 0n,
        data: callData,
      };

      const challengeHash = await account.getChallenge(call);
      const webAuthnSignature = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
      const signature = encodeChallenge(adminKeypair.publicKey, webAuthnSignature);

      await account.execute({ call, signature });

      expect(await testContract.value()).to.equal(123);

      const tamperedCall = {
        target: await testContract.getAddress(),
        value: 0n,
        data: testContract.interface.encodeFunctionData('setValue', [999]), // Different value
      };

      await expect(account.execute({ call: tamperedCall, signature })).to.be.revertedWithCustomError(
        account,
        'InvalidExecutorSignature',
      );

      await expect(account.execute({ call, signature })).to.be.revertedWithCustomError(
        account,
        'InvalidExecutorSignature',
      );

      const messageHash = ethers.id('Test message');
      const webAuthnSig = signWebAuthnChallenge(adminKeypair.keyPair.privateKey, ethers.getBytes(messageHash));
      const erc1271Signature = encodeChallenge(adminKeypair.publicKey, webAuthnSig);

      const result = await account.isValidSignature(messageHash, erc1271Signature);
      expect(result).to.equal('0x1626ba7e');

      const wrongSignerSig = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(messageHash));
      const wrongErc1271Signature = encodeChallenge(userKeypair.publicKey, wrongSignerSig);

      const wrongResult = await account.isValidSignature(messageHash, wrongErc1271Signature);
      expect(wrongResult).to.equal('0xffffffff');
    });
  });
});
