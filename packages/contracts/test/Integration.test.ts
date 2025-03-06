import { expect } from 'chai';
import { ethers } from 'hardhat';
import type { Account } from '../typechain-types';
import { setupTestEnvironment } from './helpers/testSetup';
import { createBatchCall, createSignedAdminAction, createSignedCall } from './helpers/WebAuthnSignatures';

describe('Account and AccountRegistry Integration', function () {
  // Account Role enum for testing
  const Role = {
    NONE: 0,
    EXECUTOR: 1,
    ADMIN: 2,
  };

  describe('Full Account Lifecycle', function () {
    it('should create a user account with initial admin key', async function () {
      // Load fixture with all contracts and keypairs
      const { accountRegistry, adminKeypair } = await setupTestEnvironment();

      // Use real admin key
      const adminPublicKey = adminKeypair.publicKey;

      // Create a user account
      const tx = await accountRegistry.createUser(adminPublicKey);
      const receipt = await tx.wait();
      const event = receipt.events?.find((e) => e.event === 'UserCreated');
      if (!event) throw new Error('UserCreated event not found');
      const accountAddress = event.args.account;

      // Get the created account
      const Account = await ethers.getContractFactory('Account');
      const account = Account.attach(accountAddress) as Account;

      // Verify the key is registered as admin
      const keyRole = await account.getKeyRole(adminPublicKey);
      expect(keyRole).to.equal(Role.ADMIN);
    });

    it('should execute operations with real signatures', async function () {
      // Load fixture with all contracts and keypairs
      const { accountRegistry, testContract, adminKeypair, executorKeypair } = await setupTestEnvironment();

      // Create user with admin key
      const adminPublicKey = adminKeypair.publicKey;
      const tx = await accountRegistry.createUser(adminPublicKey);
      const receipt = await tx.wait();
      const event = receipt.events?.find((e) => e.event === 'UserCreated');
      if (!event) throw new Error('UserCreated event not found');
      const accountAddress = event.args.account;

      // Get the account contract
      const Account = await ethers.getContractFactory('Account');
      const account = Account.attach(accountAddress) as Account;

      // Add executor key using real admin signature
      const executorPublicKey = executorKeypair.publicKey;

      // Create key request
      await accountRegistry.requestAddKey(accountAddress, executorPublicKey, Role.EXECUTOR);

      // Get the request ID
      const requestId = await account.getKeyRequestId(executorPublicKey);

      // Approve key request with real admin signature
      const approveData = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'uint256'], [requestId, Role.EXECUTOR]);

      const adminAction = createSignedAdminAction(
        1, // APPROVE_KEY operation
        approveData,
        0, // nonce
        adminKeypair,
      );

      await account.approveKeyRequest(adminAction.operation, adminAction.operationData, adminAction.nonce, adminAction.signature);

      // Now execute a call with executor key
      const callData = testContract.interface.encodeFunctionData('setValue', [42]);

      const call = {
        target: await testContract.getAddress(),
        value: 0,
        data: callData,
      };

      const signedCall = createSignedCall(call, executorKeypair);

      await account.execute(signedCall.call, signedCall.signature);

      // Verify the call was executed
      expect(await testContract.value()).to.equal(42);
      expect(await testContract.lastCaller()).to.equal(accountAddress);
    });

    it('should execute batch operations with real signatures', async function () {
      // Load fixture with all contracts and keypairs
      const { accountRegistry, testContract, adminKeypair } = await setupTestEnvironment();

      // Create user with admin key
      const adminPublicKey = adminKeypair.publicKey;
      const tx = await accountRegistry.createUser(adminPublicKey);
      const receipt = await tx.wait();
      const event = receipt.events?.find((e) => e.event === 'UserCreated');
      if (!event) throw new Error('UserCreated event not found');
      const accountAddress = event.args.account;

      // Get the account contract
      const Account = await ethers.getContractFactory('Account');
      const account = Account.attach(accountAddress) as Account;

      // Prepare multiple calls
      const call1Data = testContract.interface.encodeFunctionData('setValue', [100]);
      const call2Data = testContract.interface.encodeFunctionData('setMessage', ['Hello from WebAuthn']);

      const targetAddress = await testContract.getAddress();
      const calls = [
        {
          target: targetAddress,
          value: 0,
          data: call1Data,
        },
        {
          target: targetAddress,
          value: 0,
          data: call2Data,
        },
      ];

      // Create batch call with real admin signature
      const batchCall = createBatchCall(calls, adminKeypair);

      // Execute the batch call
      await account.executeBatch(batchCall.calls, batchCall.signature);

      // Verify both calls were executed
      expect(await testContract.value()).to.equal(100);
      expect(await testContract.message()).to.equal('Hello from WebAuthn');
      expect(await testContract.lastCaller()).to.equal(accountAddress);
    });
  });
});
