import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import hre, { ethers } from 'hardhat';
import { deployContracts, generateTestKeypair } from './helpers/testSetup';
import { extractEvents } from './utils';

describe('AccountRegistry Contract', function () {
  describe('Construction', function () {
    it('should initialize with the correct factory address', async function () {
      const { accountRegistry, accountFactory } = await loadFixture(deployContracts);

      expect(await accountRegistry.factory()).to.equal(await accountFactory.getAddress());
    });
  });

  describe('User Creation', function () {
    it('should create a new user and account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      const tx = await accountRegistry.createUser(keypair.credentialId, keypair.publicKey);
      const receipt = await tx.wait();

      // Verify the UserCreated event was emitted
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');

      expect(userCreatedEvents).to.not.be.undefined;
      expect(userCreatedEvents.length).to.be.at.least(1);

      // Check that the account address is not zero
      expect(userCreatedEvents[0].args.account).to.not.equal(ethers.ZeroAddress);

      // Verify account exists in registry
      const accountAddress = userCreatedEvents[0].args.account;
      const user = await accountRegistry.getUser(accountAddress);
      expect(user.publicKey.x).to.equal(keypair.publicKey.x);
      expect(user.publicKey.y).to.equal(keypair.publicKey.y);
    });

    it('should create unique accounts for different keypairs', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair1 = generateTestKeypair();
      const keypair2 = generateTestKeypair();

      // Create two users with different keys
      const tx1 = await accountRegistry.createUser(keypair1.credentialId, keypair1.publicKey);
      const receipt1 = await tx1.wait();

      const tx2 = await accountRegistry.createUser(keypair2.credentialId, keypair2.publicKey);
      const receipt2 = await tx2.wait();

      // Extract account addresses from events
      const userCreatedEvents1 = extractEvents(receipt1, accountRegistry, 'UserCreated');
      const userCreatedEvents2 = extractEvents(receipt2, accountRegistry, 'UserCreated');

      expect(userCreatedEvents1).to.have.length.gt(0);
      expect(userCreatedEvents2).to.have.length.gt(0);

      const accountAddress1 = userCreatedEvents1[0].args.account;
      const accountAddress2 = userCreatedEvents2[0].args.account;

      // Verify addresses are unique
      expect(accountAddress1).to.not.equal(accountAddress2);
    });

    it('should link the initial credential to the account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Create a user
      const tx = await accountRegistry.createUser(keypair.credentialId,keypair.publicKey);
      await tx.wait();

      // Check if credential is linked
      const [isLinked, linkedAccount] = await accountRegistry.isCredentialLinked(keypair.credentialId);
      expect(isLinked).to.be.true;
      expect(linkedAccount).to.not.equal(ethers.ZeroAddress);
    });

    it('should emit the correct events', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Create a user
      const tx = await accountRegistry.createUser(keypair.credentialId, keypair.publicKey);
      const receipt = await tx.wait();

      // Check for UserCreated event
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');

      expect(userCreatedEvents.length).to.equal(1);
      expect(userCreatedEvents[0].args.publicKey.x).to.equal(keypair.publicKey.x);
      expect(userCreatedEvents[0].args.publicKey.y).to.equal(keypair.publicKey.y);

      // Check for CredentialLinked event
      const credentialLinkedEvents = extractEvents(receipt, accountRegistry, 'CredentialLinked');

      expect(credentialLinkedEvents.length).to.equal(1);
      expect(credentialLinkedEvents[0].args.account).to.equal(userCreatedEvents[0].args.account);
    });
  });

  describe('Credential Management', function () {
    it('should prevent linking a credential to multiple accounts', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Create first user with the credential
      await accountRegistry.createUser(keypair.credentialId, keypair.publicKey);

      // Attempt to create second user with the same credential
      await expect(accountRegistry.createUser(keypair.credentialId, keypair.publicKey)).to.be.revertedWithCustomError(
        accountRegistry,
        'CredentialAlreadyUnlinked',
      );
    });

    it('should allow checking if a credential is linked', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();
      const unusedKeypair = generateTestKeypair();

      // Create a user
      const tx = await accountRegistry.createUser(keypair.credentialId, keypair.publicKey);
      const receipt = await tx.wait();

      // Extract account address
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');
      const accountAddress = userCreatedEvents[0].args.account;

      // Check if the used credential is linked
      const [isLinked, linkedAccount] = await accountRegistry.isCredentialLinked(keypair.credentialId);
      expect(isLinked).to.be.true;
      expect(linkedAccount).to.equal(accountAddress);

      // Check if an unused credential is not linked
      const [isUnusedLinked, unusedLinkedAccount] = await accountRegistry.isCredentialLinked(unusedKeypair.credentialId);
      expect(isUnusedLinked).to.be.false;
      expect(unusedLinkedAccount).to.equal(ethers.ZeroAddress);
    });
  });

  describe('Account Lookup', function () {
    it('should retrieve user information by account address', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Create a user
      const tx = await accountRegistry.createUser(keypair.credentialId, keypair.publicKey);
      const receipt = await tx.wait();

      // Get the account address from the event
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');
      const accountAddress = userCreatedEvents[0].args.account;

      // Retrieve and check user info
      const user = await accountRegistry.getUser(accountAddress);
      expect(user.publicKey.x).to.equal(keypair.publicKey.x);
      expect(user.publicKey.y).to.equal(keypair.publicKey.y);
      expect(ethers.hexlify(user.credentialId)).to.equal(ethers.hexlify(keypair.credentialId));
    });

    it('should revert when looking up a non-existent account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);

      // Attempt to look up a random, non-existent account
      await expect(
        accountRegistry.getUser(ethers.Wallet.createRandom().address),
      ).to.be.revertedWithCustomError(accountRegistry, 'UserNotFound');
    });
  });

  describe('Credential Request Functionality', function () {
    it('should allow requesting to add a credential to an account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const adminKeypair = generateTestKeypair();
      const newKeypair = generateTestKeypair();

      // Create a user with admin credential
      const tx = await accountRegistry.createUser(adminKeypair.credentialId, adminKeypair.publicKey);
      const receipt = await tx.wait();

      // Get the account address
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');
      const accountAddress = userCreatedEvents[0].args.account;

      // Request adding a new credential (Role.EXECUTOR = 1)
      const requestTx = await accountRegistry.requestAddCredential(newKeypair.credentialId, accountAddress, newKeypair.publicKey, 1);
      const requestReceipt = await requestTx.wait();

      // Check that CredentialRequestCreated event was emitted
      const credentialRequestEvents = extractEvents(requestReceipt, accountRegistry, 'CredentialRequestCreated');
      expect(credentialRequestEvents.length).to.equal(1);
      expect(credentialRequestEvents[0].args.account).to.equal(accountAddress);
      
      // For indexed bytes parameters, verify the keccak256 hash matches
      const expectedHash = ethers.keccak256(newKeypair.credentialId);
      expect(credentialRequestEvents[0].args.credentialId.hash).to.equal(expectedHash);
      expect(credentialRequestEvents[0].args.role).to.equal(1); // Role.EXECUTOR
      
      // 2. Verify that the credential is not yet linked (it's in pending state)
      const [isLinked, linkedAccount] = await accountRegistry.isCredentialLinked(newKeypair.credentialId);
      expect(isLinked).to.be.false;
      expect(linkedAccount).to.equal(ethers.ZeroAddress);
      
      // 3. Additional verification: trying to request the same credential again should fail
      // with CredentialAlreadyExists in the Account contract
      await expect(
        accountRegistry.requestAddCredential(newKeypair.credentialId, accountAddress, newKeypair.publicKey, 1)
      ).to.be.reverted; // This should fail because the credential is now in pending state
    });

    it('should revert when requesting to add a credential to a non-existent account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Try to request a credential for a non-existent account
      await expect(
        accountRegistry.requestAddCredential(ethers.randomBytes(32), ethers.Wallet.createRandom().address, keypair.publicKey, 1),
      ).to.be.revertedWithCustomError(accountRegistry, 'AccountNotRegistered');
    });

    it('should revert when requesting to add a credential that is already linked', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const adminKeypair = generateTestKeypair();
      const newKeypair = generateTestKeypair();

      // Create first user with admin credential
      const tx1 = await accountRegistry.createUser(adminKeypair.credentialId, adminKeypair.publicKey);
      const receipt1 = await tx1.wait();

      // Create second user with the new credential
      await accountRegistry.createUser(newKeypair.credentialId, newKeypair.publicKey);

      // Get the first account address
      const userCreatedEvents = extractEvents(receipt1, accountRegistry, 'UserCreated');
      const accountAddress = userCreatedEvents[0].args.account;

      // Try to add the already linked credential to the first account
      await expect(
        accountRegistry.requestAddCredential(newKeypair.credentialId, accountAddress, newKeypair.publicKey, 1),
      ).to.be.revertedWithCustomError(accountRegistry, 'CredentialAlreadyUnlinked');
    });

    it('should properly store credential in pending state until approved', async function() {
      const { accountRegistry } = await loadFixture(deployContracts);
      const adminKeypair = generateTestKeypair();
      const newKeypair = generateTestKeypair();

      // Create a user with admin credential
      const tx = await accountRegistry.createUser(adminKeypair.credentialId, adminKeypair.publicKey);
      const receipt = await tx.wait();

      // Get the account address
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');
      const accountAddress = userCreatedEvents[0].args.account;

      // Request adding a new credential
      await accountRegistry.requestAddCredential(newKeypair.credentialId, accountAddress, newKeypair.publicKey, 1);

      // The credential should not be linked in the registry yet (it's pending approval)
      const [isLinked, linkedAccount] = await accountRegistry.isCredentialLinked(newKeypair.credentialId);
      expect(isLinked).to.be.false;
      expect(linkedAccount).to.equal(ethers.ZeroAddress);

      // Get the Account contract instance
      const account = await ethers.getContractAt('Account', accountAddress);
      
      // Check credential info - should exist but in pending state
      const credentialInfo = await account.getCredentialInfo(newKeypair.credentialId);
      expect(credentialInfo.publicKey.x).to.equal(newKeypair.publicKey.x);
      expect(credentialInfo.publicKey.y).to.equal(newKeypair.publicKey.y);
      expect(credentialInfo.role).to.equal(1); // Role.EXECUTOR
      expect(credentialInfo.pending).to.be.true;
    });
  });

  describe('Credential Management Notification', function () {
    it('should revert notifyCredentialAdded when called by non-registered account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Call notifyCredentialAdded from a non-registered address
      await expect(accountRegistry.notifyCredentialAdded(keypair.credentialId)).to.be.revertedWithCustomError(
        accountRegistry,
        'AccountNotRegistered',
      );
    });

    it('should revert notifyCredentialRemoved when called by non-registered account', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const keypair = generateTestKeypair();

      // Call notifyCredentialRemoved from a non-registered address
      await expect(accountRegistry.notifyCredentialRemoved(keypair.credentialId)).to.be.revertedWithCustomError(
        accountRegistry,
        'AccountNotRegistered',
      );
    });

    it('should revert notifyCredentialRemoved when credential not found', async function () {
      const { accountRegistry } = await loadFixture(deployContracts);
      const adminKeypair = generateTestKeypair();
      const unusedKeypair = generateTestKeypair();
      const [owner] = await ethers.getSigners();

      // Create a user
      const tx = await accountRegistry.createUser(adminKeypair.credentialId, adminKeypair.publicKey);
      const receipt = await tx.wait();

      // Get the account address
      const userCreatedEvents = extractEvents(receipt, accountRegistry, 'UserCreated');
      const accountAddress = userCreatedEvents[0].args.account;

      // Impersonate the account to call notifyCredentialRemoved with an unlinked credential
      await hre.network.provider.request({
        method: 'hardhat_impersonateAccount',
        params: [accountAddress],
      });

      // Fund the impersonated account with ETH
      await owner.sendTransaction({
        to: accountAddress,
        value: ethers.parseEther('1.0'),
      });

      const accountSigner = await ethers.getSigner(accountAddress);

      const registryAsAccount = accountRegistry.connect(accountSigner);
      await expect(registryAsAccount.notifyCredentialRemoved(unusedKeypair.credentialId)).to.be.revertedWithCustomError(
        accountRegistry,
        'CredentialNotFound',
      );

      await hre.network.provider.request({
        method: 'hardhat_stopImpersonatingAccount',
        params: [accountAddress],
      });
    });
  });
});
