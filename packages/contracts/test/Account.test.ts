import { encodeChallenge } from '@appliedblockchain/giano-common';
import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import type { BytesLike, Indexed } from 'ethers';
import { ethers } from 'hardhat';
import type { Account, AccountRegistry } from '../typechain-types';
import type { PublicKeyCredential } from './helpers/testSetup';
import { deployContracts, generateTestKeypair } from './helpers/testSetup';
import { extractEvents, signWebAuthnChallenge } from './utils';

/**
 * Helper functions for common test operations
 */

/**
 * Get an admin action with signature for specified operation
 * @param account Account contract
 * @param adminKeyPair Admin keypair to sign with
 * @param operation Admin operation code
 * @param operationData ABI encoded operation data
 * @returns Signed admin action object
 */
async function getSignedAdminAction(
  account: Account,
  adminKeyPair: PublicKeyCredential,
  operation: number,
  operationData: string,
) {
  const adminNonce = await account.getAdminNonce();

  const adminAction = {
    operation,
    operationData,
    nonce: Number(adminNonce),
    signature: '0x', // Will be set below
  };

  const challengeHash = await account.getAdminChallenge(adminAction);
  adminAction.signature = encodeChallenge(
    adminKeyPair.credentialId,
    signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
  );

  return adminAction;
}

async function createAndGetAccount(
  adminKeyPair: PublicKeyCredential,
  accountRegistry: AccountRegistry,
): Promise<Account> {
  const tx = await accountRegistry.createUser(adminKeyPair.credentialId, adminKeyPair.publicKey);
  const receipt = await tx.wait();

  const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');

  if (!userCreatedEvents?.length || !userCreatedEvents[0].args) {
    throw new Error('UserCreated event not found');
  }

  const accountAddress = userCreatedEvents[0].args.account;
  return await ethers.getContractAt('Account', accountAddress);
}

/**
 * Request a credential to be added to an account
 * @param account Account contract instance
 * @param accountRegistry Registry contract instance
 * @param credentialToAdd Credential to add
 * @param role Role to assign to the credential
 * @returns The request ID
 */
async function requestAddCredential(
  account: Account,
  accountRegistry: AccountRegistry,
  credentialToAdd: PublicKeyCredential,
  role: number,
): Promise<void> {
  const accountAddress = await account.getAddress();
  await accountRegistry.requestAddCredential(
    credentialToAdd.credentialId,
    accountAddress,
    credentialToAdd.publicKey,
    role,
  );
}

/**
 * Approve a credential request
 * @param account Account contract instance
 * @param adminKeyPair Admin keypair to sign with
 * @param credentialId ID of the credential to approve
 */
async function approveKeyRequest(
  account: Account,
  adminKeyPair: PublicKeyCredential,
  credentialId: BytesLike,
): Promise<void> {
  const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [credentialId]);
  const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData); // 0 = APPROVE_CREDENTIAL_REQUEST
  await account.approveCredentialRequest(credentialId, adminAction);
}

/**
 * Creates a signedAction for pausing an account
 * @param account Account contract instance
 * @param adminKeyPair Admin keypair to sign with
 * @param pauseUntil Timestamp until when the account should be paused
 * @returns Signed admin action for pausing
 */
async function getPauseAccountAction(account: Account, adminKeyPair: PublicKeyCredential, pauseUntil: number) {
  const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
  return await getSignedAdminAction(account, adminKeyPair, 4, pauseData); // 4 = PAUSE_ACCOUNT
}

/**
 * Creates a signedAction for unpausing an account
 * @param account Account contract instance
 * @param adminKeyPair Admin keypair to sign with
 * @returns Signed admin action for unpausing
 */
async function getUnpauseAccountAction(account: Account, adminKeyPair: PublicKeyCredential) {
  return await getSignedAdminAction(account, adminKeyPair, 5, '0x'); // 5 = UNPAUSE_ACCOUNT, no data needed
}

/**
 * Sign a call to be executed by the account
 * @param account Account contract instance
 * @param keypair Keypair to sign with
 * @param call The call object to sign
 * @returns Signed call object ready for execution
 */
async function signCall(
  account: Account,
  keypair: PublicKeyCredential,
  call: { target: string; value: bigint; data: string },
) {
  const challengeHash = await account.getChallenge(call);
  const webAuthnSignature = signWebAuthnChallenge(keypair.keyPair.privateKey, ethers.getBytes(challengeHash));
  const signature = encodeChallenge(keypair.credentialId, webAuthnSignature);
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
  keypair: PublicKeyCredential,
  calls: { target: string; value: bigint; data: string }[],
) {
  const challengeHash = await account.getBatchChallenge(calls);
  const webAuthnSignature = signWebAuthnChallenge(keypair.keyPair.privateKey, ethers.getBytes(challengeHash));
  const signature = encodeChallenge(keypair.credentialId, webAuthnSignature);
  return { calls, signature };
}

describe('Account Contract', function () {
  describe('Initialization', function () {
    it('should initialize with correct registry address', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      expect(await account.registry()).to.equal(await accountRegistry.getAddress());
    });

    it('should set up the initial admin credential correctly', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      const credentialInfo = await account.getCredentialInfo(adminKeyPair.credentialId);
      expect(credentialInfo.publicKey.x).to.equal(adminKeyPair.publicKey.x);
      expect(credentialInfo.publicKey.y).to.equal(adminKeyPair.publicKey.y);
      expect(credentialInfo.role).to.equal(2); // Role.ADMIN = 2
    });

    it('should start with admin credential count of 1', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      expect(await account.getAdminKeyCount()).to.equal(1);
    });

    it('should start with nonces at 0', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      expect(await account.getNonce()).to.equal(0); // Transaction nonce
      expect(await account.getAdminNonce()).to.equal(0); // Admin nonce
    });

    it('should not be paused initially', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      const [isPaused, pausedUntil] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntil).to.equal(0);
    });
  });

  describe('Key Management', function () {
    describe('Key Requests', function () {
      it('should allow registry to request adding a credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        const tx = await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const receipt = await tx.wait();
        const keyRequestedEvents = extractEvents(receipt, account, 'CredentialRequestCreated');

        expect(keyRequestedEvents?.length).to.be.greaterThan(0);
        expect(keyRequestedEvents?.[0].args.publicKey.x).to.equal(executorKeypair.publicKey.x);
        expect(keyRequestedEvents?.[0].args.publicKey.y).to.equal(executorKeypair.publicKey.y);
        expect(keyRequestedEvents?.[0].args.requestedRole).to.equal(1); // Role.EXECUTOR = 1
      });

      it('should emit CredentialRequestCreated event with correct parameters', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await expect(
          accountRegistry.requestAddCredential(
            executorKeypair.credentialId,
            accountAddress,
            executorKeypair.publicKey,
            1, // Role.EXECUTOR = 1
          ),
        )
          .to.emit(account, 'CredentialRequestCreated')
          .withArgs(
            (credentialIdIndexed: Indexed) =>
              credentialIdIndexed.hash === ethers.keccak256(executorKeypair.credentialId),
            (publicKey: any) => {
              return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
            },
            1, // Role.EXECUTOR = 1
          );
      });

      it('should reject requests for keys that already exist', async function () {
        const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await expect(
          accountRegistry.requestAddCredential(
            adminKeyPair.credentialId,
            accountAddress,
            adminKeyPair.publicKey,
            2, // Role.ADMIN = 2
          ),
        ).to.be.revertedWithCustomError(accountRegistry, 'CredentialAlreadyLinked');
      });

      it('should only allow registry to request keys', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair, user1 } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        await expect(
          account.connect(user1).requestAddCredential(
            executorKeypair.credentialId,
            executorKeypair.publicKey,
            1, // Role.EXECUTOR = 1
          ),
        ).to.be.revertedWithCustomError(account, 'OnlyRegistryCanAddCredentials');
      });
    });

    describe('Key Request Approval', function () {
      it('should add a credential when request is approved by admin', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        await requestAddCredential(account, accountRegistry, executorKeypair, 1); // Role.EXECUTOR = 1

        await approveKeyRequest(account, adminKeyPair, executorKeypair.credentialId);

        const credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
        expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR = 1
      });

      it('should increment admin credential count when adding admin credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        const initialAdminKeyCount = await account.getAdminKeyCount();
        expect(initialAdminKeyCount).to.equal(1);

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const newAdminKeyCount = await account.getAdminKeyCount();
        expect(newAdminKeyCount).to.equal(2);
      });

      it('should emit CredentialRequestApproved and CredentialAdded events', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await expect(account.approveCredentialRequest(executorKeypair.credentialId, adminAction))
          .to.emit(account, 'CredentialRequestApproved')
          .withArgs(
            (indexedId: Indexed) => indexedId.hash === ethers.keccak256(executorKeypair.credentialId),
            (publicKey: any) => {
              return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
            },
            1, // Role.EXECUTOR = 1
          )
          .and.to.emit(account, 'CredentialAdded')
          .withArgs((publicKey: any) => {
            return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
          }, 1); // Role.EXECUTOR = 1
      });

      it('should remove the credential request after approval', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const newAdminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await expect(account.approveCredentialRequest(executorKeypair.credentialId, newAdminAction))
          .to.be.revertedWithCustomError(account, 'CredentialDoesNotExist')
          .withArgs(executorKeypair.credentialId);
      });

      it('should notify registry about the added credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await expect(account.approveCredentialRequest(executorKeypair.credentialId, adminAction)).to.emit(
          accountRegistry,
          'CredentialLinked',
        );

        const [isLinked, linkedAccount] = await accountRegistry.isCredentialLinked(executorKeypair.credentialId);
        expect(isLinked).to.be.true;
        expect(linkedAccount).to.equal(accountAddress);
      });

      it('should only allow approved requests with valid signatures', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          userKeypair.credentialId,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(
          account.approveCredentialRequest(executorKeypair.credentialId, adminAction),
        ).to.be.revertedWithCustomError(account, 'InvalidAdminSignature');
      });

      it('should validate operation data matches request ID', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        await accountRegistry.requestAddCredential(
          userKeypair.credentialId,
          accountAddress,
          userKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await expect(
          account.approveCredentialRequest(executorKeypair.credentialId, adminAction),
        ).to.be.revertedWithCustomError(account, 'InvalidOperationData');
      });
    });

    describe('Key Request Rejection', function () {
      it('should reject a credential request when called by admin', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 1, operationData);

        await account.rejectCredentialRequest(executorKeypair.credentialId, adminAction);

        const credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
        expect(credentialInfo.role).to.equal(0); // Role.NONE = 0
      });

      it('should emit CredentialRequestRejected event', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 1, operationData);

        await expect(account.rejectCredentialRequest(executorKeypair.credentialId, adminAction))
          .to.emit(account, 'CredentialRequestRejected')
          .withArgs((indexed: Indexed) => indexed.hash === ethers.keccak256(executorKeypair.credentialId));
      });

      it('should remove the credential request after rejection', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 1, operationData);

        await account.rejectCredentialRequest(executorKeypair.credentialId, adminAction);

        const newOperationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const newAdminAction = await getSignedAdminAction(account, adminKeyPair, 1, newOperationData);

        await expect(account.rejectCredentialRequest(executorKeypair.credentialId, newAdminAction))
          .to.be.revertedWithCustomError(account, 'CredentialDoesNotExist')
          .withArgs(executorKeypair.credentialId);
      });

      it('should fail when credential does not exist', async function () {
        const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const nonExistentRequestId = ethers.randomBytes(32);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [nonExistentRequestId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 1, operationData);

        await expect(account.rejectCredentialRequest(nonExistentRequestId, adminAction))
          .to.be.revertedWithCustomError(account, 'CredentialDoesNotExist')
          .withArgs(nonExistentRequestId);
      });

      it('should only allow rejection with valid admin signature', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 1, operationData);

        const challengeHash = await account.getAdminChallenge(adminAction);

        adminAction.signature = encodeChallenge(
          userKeypair.credentialId,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(
          account.rejectCredentialRequest(executorKeypair.credentialId, adminAction),
        ).to.be.revertedWithCustomError(account, 'InvalidAdminSignature');
      });
    });

    describe('Key Removal', function () {
      it('should remove an existing credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        let credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
        expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR = 1

        const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const removeKeyAction = await getSignedAdminAction(account, adminKeyPair, 2, removeKeyData);

        await account.removeCredential(executorKeypair.credentialId, removeKeyAction);

        credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
        expect(credentialInfo.role).to.equal(0); // Role.NONE = 0
      });

      it('should fail to remove a non-existent credential', async function () {
        const { accountRegistry, adminKeyPair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [userKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 2, operationData);

        await expect(account.removeCredential(userKeypair.credentialId, adminAction))
          .to.be.revertedWithCustomError(account, 'CredentialDoesNotExist')
          .withArgs(userKeypair.credentialId);
      });

      it('should decrement admin credential count when removing admin credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        expect(await account.getAdminKeyCount()).to.equal(2);

        const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const removeKeyAction = await getSignedAdminAction(account, adminKeyPair, 2, removeKeyData);

        await account.removeCredential(executorKeypair.credentialId, removeKeyAction);

        expect(await account.getAdminKeyCount()).to.equal(1);
      });

      it('should prevent removing the last admin credential', async function () {
        const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        expect(await account.getAdminKeyCount()).to.equal(1);

        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [adminKeyPair.credentialId]);

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_CREDENTIAL = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeyPair.credentialId,
          signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.removeCredential(adminKeyPair.credentialId, adminAction)).to.be.revertedWithCustomError(
          account,
          'LastAdminCredential',
        );
      });

      it('should emit CredentialRemoved event', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const removeKeyAction = await getSignedAdminAction(account, adminKeyPair, 2, removeKeyData);

        await expect(account.removeCredential(executorKeypair.credentialId, removeKeyAction))
          .to.emit(account, 'CredentialRemoved')
          .withArgs((indexed: Indexed) => {
            return indexed.hash === ethers.keccak256(executorKeypair.credentialId);
          });
      });

      it('should notify registry about the removed credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const [isLinked, linkedAccount] = await accountRegistry.isCredentialLinked(executorKeypair.credentialId);
        expect(isLinked).to.be.true;
        expect(linkedAccount).to.equal(accountAddress);

        const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const removeKeyAction = await getSignedAdminAction(account, adminKeyPair, 2, removeKeyData);

        await expect(account.removeCredential(executorKeypair.credentialId, removeKeyAction)).to.emit(
          accountRegistry,
          'CredentialUnlinked',
        );

        const [isStillLinked, _] = await accountRegistry.isCredentialLinked(executorKeypair.credentialId);
        expect(isStillLinked).to.be.false;
      });

      it('should only allow removal with valid admin signature', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const removeKeyData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const removeKeyAction = await getSignedAdminAction(account, adminKeyPair, 2, removeKeyData);

        removeKeyAction.signature = encodeChallenge(
          executorKeypair.credentialId,
          signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.randomBytes(32)),
        );

        await expect(
          account.removeCredential(executorKeypair.credentialId, removeKeyAction),
        ).to.be.revertedWithCustomError(account, 'InvalidAdminSignature');
      });
    });

    describe('Key Role Changes', function () {
      it('should emit CredentialRoleChanged event', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const changeKeyRoleData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [executorKeypair.credentialId, 2],
        ); // Role.ADMIN = 2
        const changeKeyRoleAction = await getSignedAdminAction(account, adminKeyPair, 3, changeKeyRoleData);

        await expect(account.changeCredentialRole(executorKeypair.credentialId, 2, changeKeyRoleAction))
          .to.emit(account, 'CredentialRoleChanged')
          .withArgs((publicKey: any) => {
            return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
          }, 2); // Role.ADMIN = 2
      });

      it('should change role of an existing credential', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        let credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
        expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR = 1

        const changeKeyRoleData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [executorKeypair.credentialId, 2],
        ); // Role.ADMIN = 2

        const changeKeyRoleAction = await getSignedAdminAction(account, adminKeyPair, 3, changeKeyRoleData);

        await account.changeCredentialRole(executorKeypair.credentialId, 2, changeKeyRoleAction); // Role.ADMIN = 2

        credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
        expect(credentialInfo.role).to.equal(2); // Role.ADMIN = 2
      });

      it('should fail to change role of a non-existent credential', async function () {
        const { accountRegistry, adminKeyPair, userKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [userKeypair.credentialId, 2], // Role.ADMIN = 2
        );

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 3, operationData);

        await expect(account.changeCredentialRole(userKeypair.credentialId, 2, adminAction))
          .to.be.revertedWithCustomError(account, 'CredentialDoesNotExist')
          .withArgs(userKeypair.credentialId);
      });

      it('should increment admin credential count when upgrading to admin', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        const initialAdminKeyCount = await account.getAdminKeyCount();
        expect(initialAdminKeyCount).to.equal(1);

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        expect(await account.getAdminKeyCount()).to.equal(1);

        const changeKeyRoleData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [executorKeypair.credentialId, 2],
        ); // Role.ADMIN = 2

        const changeKeyRoleAction = await getSignedAdminAction(account, adminKeyPair, 3, changeKeyRoleData);

        await account.changeCredentialRole(executorKeypair.credentialId, 2, changeKeyRoleAction); // Role.ADMIN = 2

        expect(await account.getAdminKeyCount()).to.equal(2);
      });

      it('should decrement admin credential count when downgrading from admin', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          2, // Role.ADMIN = 2
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        expect(await account.getAdminKeyCount()).to.equal(2);

        const changeKeyRoleData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [executorKeypair.credentialId, 1],
        ); // Role.EXECUTOR = 1

        const changeKeyRoleAction = await getSignedAdminAction(account, adminKeyPair, 3, changeKeyRoleData);

        await account.changeCredentialRole(executorKeypair.credentialId, 1, changeKeyRoleAction); // Role.EXECUTOR = 1

        expect(await account.getAdminKeyCount()).to.equal(1);
      });

      it('should prevent removing the last admin credential', async function () {
        const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        expect(await account.getAdminKeyCount()).to.equal(1);

        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [adminKeyPair.credentialId]);

        const adminAction = {
          operation: 2, // AdminOperation.REMOVE_CREDENTIAL = 2
          operationData: operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeyPair.credentialId,
          signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(account.removeCredential(adminKeyPair.credentialId, adminAction)).to.be.revertedWithCustomError(
          account,
          'LastAdminCredential',
        );
      });

      it('should prevent downgrading the last admin credential', async function () {
        const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        expect(await account.getAdminKeyCount()).to.equal(1);

        const adminNonce = await account.getAdminNonce();
        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [adminKeyPair.credentialId, 1], // Role.EXECUTOR = 1
        );

        const adminAction = {
          operation: 3, // AdminOperation.CHANGE_CREDENTIAL_ROLE = 3
          operationData,
          nonce: Number(adminNonce),
          signature: '0x', // Will be set below
        };

        const challengeHash = await account.getAdminChallenge(adminAction);
        adminAction.signature = encodeChallenge(
          adminKeyPair.credentialId,
          signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
        );

        await expect(
          account.changeCredentialRole(adminKeyPair.credentialId, 1, adminAction),
        ).to.be.revertedWithCustomError(account, 'LastAdminCredential');
      });

      it('should emit CredentialRoleChanged event', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const changeKeyRoleData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [executorKeypair.credentialId, 2],
        ); // Role.ADMIN = 2
        const changeKeyRoleAction = await getSignedAdminAction(account, adminKeyPair, 3, changeKeyRoleData);

        await expect(account.changeCredentialRole(executorKeypair.credentialId, 2, changeKeyRoleAction))
          .to.emit(account, 'CredentialRoleChanged')
          .withArgs((publicKey: any) => {
            return publicKey.x === executorKeypair.publicKey.x && publicKey.y === executorKeypair.publicKey.y;
          }, 2); // Role.ADMIN = 2
      });

      it('should validate operation data matches credential and new role', async function () {
        const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);
        const accountAddress = await account.getAddress();

        await accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

        const changeKeyRoleData = ethers.AbiCoder.defaultAbiCoder().encode(
          ['bytes', 'uint8'],
          [executorKeypair.credentialId, 1],
        ); // Role.EXECUTOR = 1 (incorrect)

        const changeKeyRoleAction = await getSignedAdminAction(account, adminKeyPair, 3, changeKeyRoleData);

        await expect(account.changeCredentialRole(executorKeypair.credentialId, 2, changeKeyRoleAction)) // Role.ADMIN = 2
          .to.be.revertedWithCustomError(account, 'InvalidOperationData');
      });
    });
  });

  describe('Transaction Execution', function () {
    describe('Single Transactions', function () {
      it('should execute a transaction with valid signature', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const signedCall = await signCall(account, adminKeyPair, call);

        await account.execute(signedCall);

        expect(await testContract.value()).to.equal(42);
        expect(await testContract.lastCaller()).to.equal(await account.getAddress());
      });

      it('should reject execution with invalid signature', async function () {
        const { accountRegistry, adminKeyPair, userKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash));
        const signature = encodeChallenge(userKeypair.credentialId, webAuthnSignature);

        await expect(account.execute({ call, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should increment nonce after successful execution', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        expect(await account.getNonce()).to.equal(0);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await account.execute({ call, signature });

        expect(await account.getNonce()).to.equal(1);
      });

      it('should emit Executed event', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await expect(account.execute({ call, signature }))
          .to.emit(account, 'Executed')
          .withArgs(0, await testContract.getAddress(), 0, callData);
      });

      it('should pass correct value to target contract', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await account.execute({ call, signature });

        expect(await testContract.balances(await account.getAddress())).to.equal(ethToSend);
      });

      it('should forward revert reasons from target contracts', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const errorMessage = 'This operation will fail';
        const callData = testContract.interface.encodeFunctionData('willRevert', [errorMessage]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await expect(account.execute({ call, signature })).to.be.revertedWith(errorMessage);
      });

      it('should prevent execution when paused', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
        const adminAction = await getSignedAdminAction(account, adminKeyPair, 4, pauseData);

        await account.pauseAccount(pauseUntil, adminAction);

        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const txChallengeHash = await account.getChallenge(call);
        const txWebAuthnSignature = signWebAuthnChallenge(
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(txChallengeHash),
        );
        const txSignature = encodeChallenge(adminKeyPair.credentialId, txWebAuthnSignature);

        await expect(account.execute({ call, signature: txSignature }))
          .to.be.revertedWithCustomError(account, 'AccountIsPaused')
          .withArgs(pauseUntil);
      });

      it('should prevent execution by pending credentials', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        // Create account with admin
        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        // Generate a new keypair for a credential that will remain in pending state
        const pendingKeypair = generateTestKeypair();

        // Request to add the credential but don't approve it
        await accountRegistry.requestAddCredential(
          pendingKeypair.credentialId,
          account.target,
          pendingKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Verify the credential is in pending state
        const credentialInfo = await account.getCredentialInfo(pendingKeypair.credentialId);
        expect(credentialInfo.pending).to.be.true;
        expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR = 1

        // Try to execute a transaction with the pending credential
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const call = {
          target: await testContract.getAddress(),
          value: 0n,
          data: callData,
        };

        const challengeHash = await account.getChallenge(call);
        const webAuthnSignature = signWebAuthnChallenge(
          pendingKeypair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(pendingKeypair.credentialId, webAuthnSignature);

        // Execution should fail because the credential is pending
        await expect(account.execute({ call, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );

        // Verify the transaction did not execute
        expect(await testContract.value()).to.equal(0);
      });
    });

    describe('Batch Transactions', function () {
      it('should execute multiple transactions in one call', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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

        const signedBatch = await signBatchCall(account, adminKeyPair, calls);

        await account.executeBatch(signedBatch);

        expect(await testContract.value()).to.equal(42);
        expect(await testContract.message()).to.equal('Hello from batch');
        expect(await testContract.lastCaller()).to.equal(await account.getAddress());
      });

      it('should validate batch challenge correctly', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await expect(account.executeBatch({ calls: modifiedCalls, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should reject with invalid signature', async function () {
        const { accountRegistry, adminKeyPair, userKeypair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        const signature = encodeChallenge(userKeypair.credentialId, webAuthnSignature);

        await expect(account.executeBatch({ calls, signature })).to.be.revertedWithCustomError(
          account,
          'InvalidExecutorSignature',
        );
      });

      it('should increment nonce only once for the batch', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await account.executeBatch({ calls, signature });

        expect(await account.getNonce()).to.equal(1);
      });

      it('should emit one Executed event for the batch', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

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
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(challengeHash),
        );
        const signature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        await expect(account.executeBatch({ calls, signature })).to.be.revertedWith('Intentional failure');

        expect(await testContract.value()).to.equal(0); // Not 42
      });

      it('should prevent execution when paused', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        const pauseUntil = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
        const pauseData = ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [pauseUntil]);
        const adminAction = await getSignedAdminAction(account, adminKeyPair, 4, pauseData);

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
          adminKeyPair.credentialId,
          signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(batchChallengeHash)),
        );

        await expect(account.executeBatch({ calls, signature: batchSignature }))
          .to.be.revertedWithCustomError(account, 'AccountIsPaused')
          .withArgs(pauseUntil);
      });

      it('should prevent batch execution by pending credentials', async function () {
        const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

        // Create account with admin
        const account = await createAndGetAccount(adminKeyPair, accountRegistry);

        // Generate a new keypair for a credential that will remain in pending state
        const pendingKeypair = generateTestKeypair();

        // Request to add the credential but don't approve it
        await accountRegistry.requestAddCredential(
          pendingKeypair.credentialId,
          account.target,
          pendingKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        // Verify the credential is in pending state
        const credentialInfo = await account.getCredentialInfo(pendingKeypair.credentialId);
        expect(credentialInfo.pending).to.be.true;
        expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR = 1

        // Try to execute a batch transaction
        const callData = testContract.interface.encodeFunctionData('setValue', [42]);
        const batchCalls = [
          {
            target: await testContract.getAddress(),
            value: 0n,
            data: callData,
          },
        ];

        const batchChallengeHash = await account.getBatchChallenge(batchCalls);
        const batchSignature = encodeChallenge(
          pendingKeypair.credentialId,
          signWebAuthnChallenge(pendingKeypair.keyPair.privateKey, ethers.getBytes(batchChallengeHash)),
        );

        // Batch execution should also fail
        await expect(
          account.executeBatch({ calls: batchCalls, signature: batchSignature }),
        ).to.be.revertedWithCustomError(account, 'InvalidExecutorSignature');

        // Verify the transaction did not execute
        expect(await testContract.value()).to.equal(0);
      });
    });
  });

  describe('Admin Operations', function () {
    it('should validate admin signatures correctly', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);
      const accountAddress = await account.getAddress();

      const tx = await accountRegistry.requestAddCredential(
        executorKeypair.credentialId,
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

      const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

      await expect(account.approveCredentialRequest(executorKeypair.credentialId, adminAction)).to.not.be.reverted;

      const credentialInfo = await account.getCredentialInfo(executorKeypair.credentialId);
      expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR = 1
    });

    it('should increment admin nonce after operations', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);
      const accountAddress = await account.getAddress();

      const initialAdminNonce = await account.getAdminNonce();
      expect(initialAdminNonce).to.equal(0);

      const tx = await accountRegistry.requestAddCredential(
        executorKeypair.credentialId,
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
      const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

      await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

      const newAdminNonce = await account.getAdminNonce();
      expect(newAdminNonce).to.equal(1);

      const credentialId2 = ethers.randomBytes(32);
      await accountRegistry.requestAddCredential(
        credentialId2,
        accountAddress,
        { x: ethers.hexlify(ethers.randomBytes(32)), y: ethers.hexlify(ethers.randomBytes(32)) },
        1, // Role.EXECUTOR = 1
      );

      const operationData2 = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [credentialId2]);
      const adminAction2 = await getSignedAdminAction(account, adminKeyPair, 0, operationData2);

      await account.approveCredentialRequest(credentialId2, adminAction2);

      const finalAdminNonce = await account.getAdminNonce();
      expect(finalAdminNonce).to.equal(2);
    });

    it('should emit AdminActionExecuted event when executing admin operation', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);
      await requestAddCredential(account, accountRegistry, executorKeypair, 1);

      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
      const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

      await expect(account.approveCredentialRequest(executorKeypair.credentialId, adminAction))
        .to.emit(account, 'AdminActionExecuted')
        .withArgs(0, adminNonce); // AdminOperation.APPROVE_CREDENTIAL_REQUEST = 0
    });

    it('should reject operations with invalid signature', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);
      await requestAddCredential(account, accountRegistry, executorKeypair, 1);

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
      const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

      // Replace with an invalid signature
      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        userKeypair.credentialId, // Non-admin credential
        signWebAuthnChallenge(userKeypair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(
        account.approveCredentialRequest(executorKeypair.credentialId, adminAction),
      ).to.be.revertedWithCustomError(account, 'InvalidAdminSignature');
    });

    it('should increment admin nonce after admin operations', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair, userKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);
      await requestAddCredential(account, accountRegistry, executorKeypair, 1);

      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
      const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);

      await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);

      const newAdminNonce = await account.getAdminNonce();
      expect(newAdminNonce).to.equal(1);

      // Try another admin operation
      await requestAddCredential(account, accountRegistry, userKeypair, 1);
      const operationData2 = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [userKeypair.credentialId]);
      const adminAction2 = await getSignedAdminAction(account, adminKeyPair, 0, operationData2);

      await account.approveCredentialRequest(userKeypair.credentialId, adminAction2);

      const finalAdminNonce = await account.getAdminNonce();
      expect(finalAdminNonce).to.equal(2);
    });

    it('should reject operations with invalid nonce', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      await requestAddCredential(account, accountRegistry, executorKeypair, 1);

      const adminNonce = await account.getAdminNonce();

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_CREDENTIAL_REQUEST = 0
        operationData,
        nonce: Number(adminNonce) + 1, // Incorrect nonce
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.approveCredentialRequest(executorKeypair.credentialId, adminAction))
        .to.be.revertedWithCustomError(account, 'InvalidNonce')
        .withArgs(adminNonce, Number(adminNonce) + 1);
    });

    it('should reject operations with wrong operation type', async function () {
      const { accountRegistry, adminKeyPair, executorKeypair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);
      const accountAddress = await account.getAddress();

      await accountRegistry.requestAddCredential(
        executorKeypair.credentialId,
        accountAddress,
        executorKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
      const adminAction = await getSignedAdminAction(account, adminKeyPair, 1, operationData);

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.approveCredentialRequest(executorKeypair.credentialId, adminAction))
        .to.be.revertedWithCustomError(account, 'InvalidOperation')
        .withArgs(0, 1); // Expected APPROVE_CREDENTIAL_REQUEST=0, got REJECT_CREDENTIAL_REQUEST=1
    });

    it('should prevent admin operations by pending credentials', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      // Create account with admin
      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      // Generate a new keypair for a credential that will remain in pending state
      const pendingKeypair = generateTestKeypair();

      // Request to add the credential but don't approve it - give it ADMIN role
      await accountRegistry.requestAddCredential(
        pendingKeypair.credentialId,
        account.target,
        pendingKeypair.publicKey,
        2, // Role.ADMIN = 2
      );

      // Verify the credential is in pending state
      const credentialInfo = await account.getCredentialInfo(pendingKeypair.credentialId);
      expect(credentialInfo.pending).to.be.true;
      expect(credentialInfo.role).to.equal(2); // Role.ADMIN = 2

      // Create a credential request for another user that the pending admin would try to approve
      const anotherKeypair = generateTestKeypair();
      await accountRegistry.requestAddCredential(
        anotherKeypair.credentialId,
        account.target,
        anotherKeypair.publicKey,
        1, // Role.EXECUTOR = 1
      );

      // Try to approve it with the pending credential (which has admin role in pending state)
      const adminNonce = await account.getAdminNonce();
      const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [anotherKeypair.credentialId]);

      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_CREDENTIAL_REQUEST = 0
        operationData,
        nonce: Number(adminNonce),
        signature: '0x',
      };

      const adminChallengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        pendingKeypair.credentialId,
        signWebAuthnChallenge(pendingKeypair.keyPair.privateKey, ethers.getBytes(adminChallengeHash)),
      );

      // The admin operation should fail
      await expect(
        account.approveCredentialRequest(anotherKeypair.credentialId, adminAction),
      ).to.be.revertedWithCustomError(account, 'InvalidAdminSignature');
    });
  });

  describe('Pause Functionality', function () {
    it('should allow admin to pause the account', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

      const pauseUntil = Math.floor(Date.now() / 1000) + 3600;

      const adminAction = await getPauseAccountAction(account, adminKeyPair, pauseUntil);

      await expect(account.pauseAccount(pauseUntil, adminAction)).to.not.be.reverted;

      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.true;
      expect(pausedUntilTime).to.equal(pauseUntil);
    });

    it('should emit AccountPaused event with correct timestamp', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await expect(account.pauseAccount(pauseUntil, adminAction))
        .to.emit(account, 'AccountPaused')
        .withArgs(pauseUntil);
    });

    it('should prevent transaction execution while paused', async function () {
      const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
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
        adminKeyPair.keyPair.privateKey,
        ethers.getBytes(txChallengeHash),
      );
      const txSignature = encodeChallenge(adminKeyPair.credentialId, txWebAuthnSignature);

      await expect(account.execute({ call, signature: txSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(pauseUntil);

      const batchChallengeHash = await account.getBatchChallenge([call]);
      const batchWebAuthnSignature = signWebAuthnChallenge(
        adminKeyPair.keyPair.privateKey,
        ethers.getBytes(batchChallengeHash),
      );
      const batchSignature = encodeChallenge(adminKeyPair.credentialId, batchWebAuthnSignature);

      await expect(account.executeBatch({ calls: [call], signature: batchSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(pauseUntil);
    });

    it('should handle indefinite pausing', async function () {
      const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
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
        adminKeyPair.keyPair.privateKey,
        ethers.getBytes(txChallengeHash),
      );
      const txSignature = encodeChallenge(adminKeyPair.credentialId, txWebAuthnSignature);

      await expect(account.execute({ call, signature: txSignature }))
        .to.be.revertedWithCustomError(account, 'AccountIsPaused')
        .withArgs(ethers.MaxUint256);
    });

    it('should allow admin to unpause the account', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      await account.pauseAccount(pauseUntil, pauseAction);

      const unpauseAction = await getUnpauseAccountAction(account, adminKeyPair);

      await expect(account.unpauseAccount(unpauseAction)).to.not.be.reverted;

      const [isPaused, pausedUntilTime] = await account.isPaused();
      expect(isPaused).to.be.false;
      expect(pausedUntilTime).to.equal(0);
    });

    it('should emit AccountUnpaused event', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
      );

      await expect(account.unpauseAccount(unpauseAction)).to.emit(account, 'AccountUnpaused');
    });

    it('should allow transaction execution after unpausing', async function () {
      const { accountRegistry, adminKeyPair, testContract } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
      );

      await account.pauseAccount(pauseUntil, pauseAction);

      const unpauseAction = await getUnpauseAccountAction(account, adminKeyPair);

      const unpauseChallengeHash = await account.getAdminChallenge(unpauseAction);
      unpauseAction.signature = encodeChallenge(
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(unpauseChallengeHash)),
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
        adminKeyPair.keyPair.privateKey,
        ethers.getBytes(txChallengeHash),
      );
      const txSignature = encodeChallenge(adminKeyPair.credentialId, txWebAuthnSignature);

      await account.execute({ call, signature: txSignature });

      expect(await testContract.value()).to.equal(42);
    });

    it('should report pause status correctly', async function () {
      const { accountRegistry, adminKeyPair } = await loadFixture(deployContracts);

      const account = await createAndGetAccount(adminKeyPair, accountRegistry);

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
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(pauseChallengeHash)),
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
      let adminKeyPair: PublicKeyCredential;
      let executorKeypair: PublicKeyCredential;
      let nonAuthorizedKeypair: PublicKeyCredential;

      beforeEach(async function () {
        const fixture = await loadFixture(deployContracts);
        adminKeyPair = fixture.adminKeyPair;

        executorKeypair = generateTestKeypair();
        nonAuthorizedKeypair = generateTestKeypair();

        account = await createAndGetAccount(adminKeyPair, fixture.accountRegistry);

        const accountAddress = await account.getAddress();

        await fixture.accountRegistry.requestAddCredential(
          executorKeypair.credentialId,
          accountAddress,
          executorKeypair.publicKey,
          1, // Role.EXECUTOR = 1
        );

        const operationData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [executorKeypair.credentialId]);
        const adminAction = await getSignedAdminAction(account, adminKeyPair, 0, operationData);
        await account.approveCredentialRequest(executorKeypair.credentialId, adminAction);
      });

      it('should return the ERC1271 magic value for a valid signature', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));
        const webAuthnSignature = signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(messageHash));
        const encodedSignature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);
        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0x1626ba7e');
      });

      it('should return the magic value for a valid executor signature', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello from executor!'));

        const webAuthnSignature = signWebAuthnChallenge(
          executorKeypair.keyPair.privateKey,
          ethers.getBytes(messageHash),
        );

        const encodedSignature = encodeChallenge(executorKeypair.credentialId, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0x1626ba7e');
      });

      it('should not return the magic value for an invalid signature', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        const differentMessageHash = ethers.keccak256(ethers.toUtf8Bytes('Different message!'));

        const webAuthnSignature = signWebAuthnChallenge(
          adminKeyPair.keyPair.privateKey,
          ethers.getBytes(differentMessageHash),
        );

        const encodedSignature = encodeChallenge(adminKeyPair.credentialId, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0xffffffff');
      });

      it('should not return the magic value for a signature from unauthorized credential', async function () {
        const messageHash = ethers.keccak256(ethers.toUtf8Bytes('Hello, ERC1271!'));

        const webAuthnSignature = signWebAuthnChallenge(
          nonAuthorizedKeypair.keyPair.privateKey,
          ethers.getBytes(messageHash),
        );

        const encodedSignature = encodeChallenge(nonAuthorizedKeypair.credentialId, webAuthnSignature);

        const isValid = await account.isValidSignature(messageHash, encodedSignature);

        expect(isValid).to.equal('0xffffffff');
      });
    });

    describe('ERC721/ERC1155 Receiver', function () {
      let account: Account;
      let adminKeyPair: PublicKeyCredential;
      let accountRegistry: AccountRegistry;

      beforeEach(async function () {
        const fixture = await loadFixture(deployContracts);
        adminKeyPair = fixture.adminKeyPair;
        accountRegistry = fixture.accountRegistry;
        account = await createAndGetAccount(adminKeyPair, accountRegistry);
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
    let adminKeyPair: PublicKeyCredential;
    let userKeypair: PublicKeyCredential;
    let accountRegistry: AccountRegistry;

    beforeEach(async function () {
      const fixture = await loadFixture(deployContracts);
      adminKeyPair = fixture.adminKeyPair;
      accountRegistry = fixture.accountRegistry;
      account = await createAndGetAccount(adminKeyPair, accountRegistry);
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
          target: ethers.getAddress(ethers.hexlify(adminKeyPair.publicKey.x).substring(0, 42)), // Using this as a dummy address
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
        operation: 0, // AdminOperation.APPROVE_CREDENTIAL_REQUEST
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

    it('should return correct credential info for existing credential', async function () {
      const credentialInfo = await account.getCredentialInfo(adminKeyPair.credentialId);

      expect(credentialInfo.publicKey.x).to.equal(adminKeyPair.publicKey.x);
      expect(credentialInfo.publicKey.y).to.equal(adminKeyPair.publicKey.y);
      expect(credentialInfo.role).to.equal(2); // Role.ADMIN = 2
    });

    it('should return empty credential info for non-existent credential', async function () {
      const credentialInfo = await account.getCredentialInfo(userKeypair.credentialId);

      expect(credentialInfo.role).to.equal(0); // Role.NONE = 0
    });

    it('should return correct admin nonce', async function () {
      const initialNonce = await account.getAdminNonce();
      expect(initialNonce).to.equal(0);

      await accountRegistry.requestAddCredential(userKeypair.credentialId, account.target, userKeypair.publicKey, 1); // Role.EXECUTOR = 1
      const adminAction = {
        operation: 0, // AdminOperation.APPROVE_CREDENTIAL_REQUEST
        nonce: initialNonce,
        operationData: ethers.AbiCoder.defaultAbiCoder().encode(['bytes'], [userKeypair.credentialId]),
        signature: '0x',
      };

      const challengeHash = await account.getAdminChallenge(adminAction);
      adminAction.signature = encodeChallenge(
        adminKeyPair.credentialId,
        signWebAuthnChallenge(adminKeyPair.keyPair.privateKey, ethers.getBytes(challengeHash)),
      );

      await account.approveCredentialRequest(userKeypair.credentialId, adminAction);

      const finalAdminNonce = await account.getAdminNonce();
      expect(finalAdminNonce).to.equal(1);
    });
  });

  describe('Security Features', function () {
    it('should prevent reentrancy attacks', async function () {
      // Implement reentrancy attack prevention logic
    });
  });
});
