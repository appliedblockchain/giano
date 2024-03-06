import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs';
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';
import { createKeypair } from './utils';

describe('ERC721AccountFactory', () => {
  const deploy = async () => {
    const [signer] = await ethers.getSigners();
    const accountFactory = await ethers.getContractFactory('ERC721AccountFactory', signer);
    const accountFactoryContract = await accountFactory.deploy();
    await accountFactoryContract.waitForDeployment();
    return { signer, accountFactoryContract };
  };

  describe('createAccount', () => {
    it('should emit an AccountCreated event', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();

      await expect(accountFactoryContract.createAccount({ x, y }))
        .to.emit(accountFactoryContract, 'AccountCreated')
        .withArgs([x, y], anyValue);
    });
    it('should deploy a contract', async () => {
      const { accountFactoryContract } = await loadFixture(deploy);
      const { x, y } = createKeypair();

      const receipt = await (await accountFactoryContract.createAccount({ x, y })).wait();
      expect(receipt).to.exist;
      const event = accountFactoryContract.interface.parseLog(receipt!.logs[0]);
      const [, address] = event!.args;
      expect(await ethers.provider.getCode(address)).to.exist;
    });
  });
});
