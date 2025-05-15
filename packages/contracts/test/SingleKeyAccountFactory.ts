import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs';
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import { keccak256 } from 'ethers';
import { ethers } from 'hardhat';
import { createKeypair } from './utils';

describe('SingleKeyAccountFactory', () => {
  const deploy = async () => {
    const [signer] = await ethers.getSigners();
    const accountFactory = await ethers.getContractFactory('SingleKeyAccountFactory', signer);
    const randomBytes = new Uint8Array(32);
    const accountFactoryContract = await accountFactory.deploy(crypto.getRandomValues(randomBytes));
    await accountFactoryContract.waitForDeployment();
    return { signer, accountFactoryContract };
  };

  describe('createUser', () => {
    const userId = new Uint8Array([1, 2, 3]);
    it('should emit a UserCreated event', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();

      const address = await accountFactoryContract.getAccountAddress({ x, y });
      await expect(
        accountFactoryContract.createUser(userId, {
          x,
          y,
        }),
      )
        .to.emit(accountFactoryContract, 'UserCreated')
        .withArgs(userId, [x, y], address);
    });
    it('should deploy a contract', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();

      const receipt = await (await accountFactoryContract.createUser(userId, { x, y })).wait();
      expect(receipt).to.exist;
      const event = accountFactoryContract.interface.parseLog(receipt!.logs[0]);
      const [, , address] = event!.args;
      expect(await ethers.provider.getCode(address)).to.exist;
    });
    it('should revert if the user already exists', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();
      const { x: x1, y: y1 } = createKeypair();

      await accountFactoryContract.createUser(userId, { x, y });
      await expect(accountFactoryContract.createUser(userId, { x: x1, y: y1 }))
        .to.be.revertedWithCustomError(accountFactoryContract, 'UserAlreadyExists')
        .withArgs(userId);
    });
  });
});
