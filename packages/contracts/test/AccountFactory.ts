import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs';
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';
import { createKeypair } from './utils';

describe('AccountFactory', () => {
  const deploy = async () => {
    const [signer] = await ethers.getSigners();
    const accountFactory = await ethers.getContractFactory('AccountFactory', signer);
    const accountFactoryContract = await accountFactory.deploy();
    await accountFactoryContract.waitForDeployment();
    return { signer, accountFactoryContract };
  };

  describe('createUser', () => {
    it('should emit an UserCreated event', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();

      await expect(accountFactoryContract.createUser(123n, { x, y })).to.emit(accountFactoryContract, 'UserCreated').withArgs(123n, [x, y], anyValue);
    });
    it('should deploy a contract', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();

      const receipt = await (await accountFactoryContract.createUser(123n, { x, y })).wait();
      expect(receipt).to.exist;
      const event = accountFactoryContract.interface.parseLog(receipt!.logs[0]);
      const [, , address] = event!.args;
      expect(await ethers.provider.getCode(address)).to.exist;
    });
    it('should revert if the user already exists', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();
      const { x: x1, y: y1 } = createKeypair();

      await accountFactoryContract.createUser(123n, { x, y });
      await expect(accountFactoryContract.createUser(123n, { x: x1, y: y1 }))
        .to.be.revertedWithCustomError(accountFactoryContract, 'UserAlreadyExists')
        .withArgs(123n);
    });
  });
});
