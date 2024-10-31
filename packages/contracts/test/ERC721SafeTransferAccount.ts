import type { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/signers';
import { expect } from 'chai';
import type { Contract, TransactionResponse } from 'ethers';
import { ethers, ignition } from 'hardhat';
import ERC721SafeTransferAccountModule from '../ignition/modules/ERC721SafeTransferAccount';
import { ERC721SafeTransferAccountFactory__factory } from '..';
import { createKeypair } from './utils';

describe('ERC721SafeTransferAccount', () => {
  const deployFixture = async () => {
    const [signer, otherAccount] = await ethers.getSigners();
    const { accountFactory, erc721 } = await ignition.deploy(ERC721SafeTransferAccountModule);

    return { signer, otherAccount, accountFactory, erc721 };
  };

  let signer: HardhatEthersSigner, otherAccount: HardhatEthersSigner, accountFactory: Contract, erc721: Contract;

  beforeEach(async () => {
    ({ signer, otherAccount, accountFactory, erc721 } = await deployFixture());
  });

  describe('accepting ERC721.safeTransferFrom', () => {
    it('should successfully receive tokens transferred with safeTransferFrom', async () => {
      await erc721.mint(otherAccount.address);

      const { x, y } = createKeypair();

      const tx: TransactionResponse = await accountFactory.createUser(1n, { x, y });
      const receipt = await tx.wait();
      expect(receipt).to.not.be.null;
      const iface = ethers.Interface.from(ERC721SafeTransferAccountFactory__factory.abi);
      const userCreated = iface.parseLog(receipt!.logs[0]);
      const account = userCreated!.args[2];

      // Transfer the token using safeTransferFrom
      await (erc721.connect(otherAccount) as Contract).safeTransferFrom(otherAccount.address, account, 1n);

      // Verify that accountFactory now owns the token
      const newOwner = await erc721.ownerOf(1n);
      expect(newOwner).to.equal(account);
    });
  });
});
