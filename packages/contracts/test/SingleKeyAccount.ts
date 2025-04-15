import { encodeChallenge, hexToUint8Array } from '@appliedblockchain/giano-common';
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import { ethers, ignition } from 'hardhat';
import SingleKeyAccountFactoryModule from '../ignition/modules/SingleKeyAccountFactory';
import type { SingleKeyAccount } from '../typechain-types';
import { createKeypair, signWebAuthnChallenge } from './utils';
import TestingModule from '../ignition/modules/Testing';

describe('SingleKeyAccount Contract', () => {
  let account: SingleKeyAccount;
  let genericERC20: any;
  let signer: any;
  let otherSigner: any;
  let publicKey: any;
  let keypair: any;

  const deployFixture = async () => {
    const [signer, otherSigner] = await ethers.getSigners();
    const { accountFactory } = await ignition.deploy(SingleKeyAccountFactoryModule);
    const {genericERC20: erc20, genericERC721: erc721} = await ignition.deploy(TestingModule)

    return { signer, otherSigner, erc20, erc721, accountFactory };
  };

  beforeEach(async () => {
    ({ signer, otherSigner, erc20: genericERC20 } = await loadFixture(deployFixture));

    // Create keypair and deploy Account
    keypair = createKeypair();
    publicKey = {
      x: keypair.x,
      y: keypair.y,
    };

    const AccountFactory = await ethers.getContractFactory('SingleKeyAccount', signer);
    account = await AccountFactory.deploy(publicKey);
    await account.waitForDeployment();
  });

  describe('execute', () => {
    it('should execute a transfer on GenericERC20 token', async () => {
      // Mint tokens to account
      await genericERC20.transfer(account.target, ethers.parseEther('100'));

      // Prepare call data for transfer
      const recipient = otherSigner.address;
      const amount = ethers.parseEther('10');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);

      // Generate a valid signature
      const challenge = await account.getChallenge({ target: genericERC20.target, value: 0, data: transferData });
      const signature = signWebAuthnChallenge(keypair.keyPair.privateKey, hexToUint8Array(challenge));

      // Execute transfer via Account contract
      await expect(
        account.execute({
          call: {
            target: genericERC20.target,
            value: 0,
            data: transferData,
          },
          signature: encodeChallenge(null, signature),
        }),
      )
        .to.emit(genericERC20, 'Transfer')
        .withArgs(account.target, recipient, amount);

      // Check recipient balance
      const balance = await genericERC20.balanceOf(recipient);
      expect(balance).to.equal(amount);
    });

    it('should revert with InvalidSignature for incorrect signature', async () => {
      await genericERC20.transfer(account.target, ethers.parseEther('100'));

      const recipient = otherSigner.address;
      const amount = ethers.parseEther('50');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);
      const badSigData = genericERC20.interface.encodeFunctionData('transfer', [recipient, ethers.parseEther('10')]);

      const badChallenge = await account.getChallenge({ target: genericERC20.target, value: 0, data: badSigData });
      const invalidSignature = encodeChallenge(null, signWebAuthnChallenge(keypair.keyPair.privateKey, hexToUint8Array(badChallenge)));

      // Attempt to execute a transfer of 50 tokens with a signature for 10 tokens
      await expect(
        account.execute({
          call: {
            target: genericERC20.target,
            value: 0,
            data: transferData,
          },
          signature: invalidSignature,
        }),
      ).to.be.revertedWithCustomError(account, 'InvalidSignature');
    });

    it('should revert with InvalidSignature if the value parameter does not match', async () => {
      await genericERC20.transfer(account.target, ethers.parseEther('100'));

      const recipient = otherSigner.address;
      const amount = ethers.parseEther('10');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);

      const challenge = await account.getChallenge({ target: genericERC20.target, value: 0, data: transferData });
      const signature = signWebAuthnChallenge(keypair.keyPair.privateKey, hexToUint8Array(challenge));

      await expect(
        account.execute({
          call: {
            target: genericERC20.target,
            value: 50,
            data: transferData,
          },
          signature: encodeChallenge(null, signature),
        }),
      ).to.be.revertedWithCustomError(account, 'InvalidSignature');
    });

    it('should revert with InvalidSignature if the target parameter does not match', async () => {
      await genericERC20.transfer(account.target, ethers.parseEther('100'));

      const recipient = otherSigner.address;
      const amount = ethers.parseEther('10');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);

      const challenge = await account.getChallenge({ target: genericERC20.target, value: 0, data: transferData });
      const signature = signWebAuthnChallenge(keypair.keyPair.privateKey, hexToUint8Array(challenge));

      await expect(
        account.execute({
          call: {
            target: ethers.Wallet.createRandom().address,
            value: 0,
            data: transferData,
          },
          signature: encodeChallenge(null, signature),
        }),
      ).to.be.revertedWithCustomError(account, 'InvalidSignature');
    });

    it('should revert if the same signature is used twice', async () => {
      await genericERC20.transfer(account.target, ethers.parseEther('100'));

      const recipient = otherSigner.address;
      const amount = ethers.parseEther('10');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);

      const challenge = await account.getChallenge({ target: genericERC20.target, value: 0, data: transferData });
      const signature = signWebAuthnChallenge(keypair.keyPair.privateKey, hexToUint8Array(challenge));

      await account.execute({
        call: {
          target: genericERC20.target,
          value: 0,
          data: transferData,
        },
        signature: encodeChallenge(null, signature),
      });

      await expect(
        account.execute({
          call: {
            target: genericERC20.target,
            value: 0,
            data: transferData,
          },
          signature: encodeChallenge(null, signature),
        }),
      ).to.be.revertedWithCustomError(account, 'InvalidSignature');
    });
  });
  describe('ERC-1271 compliance', () => {
    it('should return the magic value when checking a valid signature', async () => {
      const hash = new Uint8Array(32);
      crypto.getRandomValues(hash);
      const signature = encodeChallenge(null, signWebAuthnChallenge(keypair.keyPair.privateKey, hash));
      const result = await account.isValidSignature(hash, signature);
      expect(result).to.equal('0x1626ba7e');
    });
    it('should return a constant value when checking an invalid signature', async () => {
      const hash = new Uint8Array(32);
      crypto.getRandomValues(hash);
      const signature = encodeChallenge(null, signWebAuthnChallenge(keypair.keyPair.privateKey, hexToUint8Array('0xDEADBEEF')));
      const result = await account.isValidSignature(hash, signature);
      expect(result).to.equal('0xffffffff');
    });
  });
});
