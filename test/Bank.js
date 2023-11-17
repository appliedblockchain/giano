import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers.js';
import { expect } from 'chai';

// We define a fixture to reuse the same setup in every test: we use loadFixture to run this setup once, snapshot that state, and reset Hardhat Network to that snapshot in every test.
async function deployFixture() {
  const [ownerAccount, account] = await ethers.getSigners();
  const Bank = await ethers.getContractFactory('Bank');
  const bank = await Bank.deploy();
  return { bank, ownerAccount, account };
}

describe('Bank', () => {
  describe('Deployment', () => {
    it('should set the right owner', async () => {
      const { bank, ownerAccount } = await loadFixture(deployFixture);
      const result = await bank.owner();
      const expected = ownerAccount.address;
      expect(result).to.equal(expected);
    });
  });

  describe('Use cases', () => {
    it('should register holder', async () => {
      const { bank, account } = await loadFixture(deployFixture);

      const tx = await bank.connect(account).register();
      await tx.wait();
      await expect(tx).to.emit(bank, 'Registration').withArgs(account.address);

      const actual = await bank.getBalance(account.address);
      const expected = 0;

      expect(actual).to.equal(expected);

      const holdersCount = await bank.holdersCount();
      expect(holdersCount).to.equal(1);

      const holder = await bank.holders(parseInt(holdersCount) - 1);
      expect(holder).to.equal(account.address);

      const balance = await bank.getBalance(account.address);
      expect(balance).to.equal(0);
    });

    it('should deposit', async () => {
      const { bank, account } = await loadFixture(deployFixture);

      const tx = await bank.connect(account).deposit('sig_123', account.address, 3);
      await tx.wait();
      await expect(tx).to.emit(bank, 'Deposit').withArgs(account.address, 'sig_123', account.address, 3);

      const actual = await bank.getBalance(account.address);
      const expected = 3;

      expect(actual).to.equal(expected);
    });
  });
});
