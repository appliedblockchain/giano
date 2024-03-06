import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import crypto from 'crypto';
import { ethers } from 'hardhat';
import { createKeypair } from './utils';

describe.skip('ERC721Account', () => {
  const deploy = async () => {
    const [signer] = await ethers.getSigners();
    const account = await ethers.getContractFactory('ERC721Account', signer);
    const { x, y, keyPair } = createKeypair();
    const accountContract = await account.deploy({ x, y });
    const token = await ethers.getContractFactory('GenericERC721', signer);
    const tokenContract = await token.deploy();
    await tokenContract.waitForDeployment();
    await accountContract.waitForDeployment();
    return { x, y, keyPair, signer, accountContract, tokenContract };
  };

  describe('transferToken', () => {
    it('should work when signed by the associated keypair', async () => {
      const { keyPair, signer, accountContract, tokenContract } = await loadFixture(deploy);

      await tokenContract.mint(accountContract.target, 1);

      const signature = crypto.sign(null, Buffer.from(''), keyPair.privateKey);

      await accountContract.transferToken(tokenContract.target, signer.address, 1, signature, 0);
    });
  });
});
