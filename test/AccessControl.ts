import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import hardhat from 'hardhat';
const { ethers } = hardhat;

const admin = {
  publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5jCn87rbZZDLc8VHJ8dxAs4hx95Y1n0__U_I8qvwG6UytkNz9Dx7WjlEDWx_fj5IjGnFKC1KN-DOVKIMRGy-oQ',
  payload: {
    id: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
    rawId: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
    response: {
      clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWVdKaiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
      authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
      signature: 'MEUCIGT47yTmzNsYrwkpdqptRTOJmBjhbcLK_tSpA8mosbVSAiEAjRCIERiV7EMvI37tDgYQp-EwhDnlba7fKsW4aDvWGMg',
    },
  },
};

const account1 = {
  publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECc0uxyi2LLgBY7uhcH2ktn-dEb-hQ_-r8o_t-kjH6OOj5pWSkXfXarsEth4ukWJLClApT9BEfgq7qCKi7zKf2g',
  payload: {
    id: '-koIHwRW4l37VmRKwlM7_OKrFqE',
    rawId: '-koIHwRW4l37VmRKwlM7_OKrFqE',
    response: {
      clientDataJSON:
        'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWVdKaiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
      authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
      signature: 'MEYCIQDqXTEcc6ZbuSkP9a3v-s5Xt3T8dSO7BJeLoPNkAmtNkgIhAMme-uK1Ti8peOWrYgqoUij-Wzzg7zGu9kWOjhUASN4Y',
    },
  },
};

// We define a fixture to reuse the same setup in every test: we use loadFixture to run this setup once, snapshot that state, and reset Hardhat Network to that snapshot in every test.
async function deployFixture() {
  const [ownerAccount, account] = await ethers.getSigners();
  const ContractWithAccessControl = await ethers.getContractFactory('Dummy');
  const accessControl = await ContractWithAccessControl.deploy(admin.publicKey);
  return { accessControl, ownerAccount, account };
}

describe('AccessControl', () => {
  describe('Deployment', () => {
    it('should set the right owner', async () => {
      const { accessControl, ownerAccount } = await loadFixture(deployFixture);
      const result = await accessControl.owner();
      const expected = ownerAccount.address;
      expect(result).to.equal(expected);
    });
  });

  describe('Use cases', () => {
    it('should grant role', async () => {
      const { accessControl } = await loadFixture(deployFixture);

      await expect(
        (
          await accessControl.grantRole(
            {
              publicKey: admin.publicKey,
              signature: admin.payload.response.signature,
              clientDataJSON: admin.payload.response.clientDataJSON,
              authenticatorData: admin.payload.response.authenticatorData,
            },
            await accessControl.ANY_ROLE(),
            account1.publicKey,
          )
        ).wait(),
      )
        .emit(accessControl, 'RoleGranted')
        .withArgs(await accessControl.ANY_ROLE(), account1.publicKey, admin.publicKey);

      const response = await accessControl.hasRole(await accessControl.ANY_ROLE(), account1.publicKey);
      expect(response).to.equal(true);
    });

    it('should revert if user does not have rights', async () => {
      const { accessControl } = await loadFixture(deployFixture);

      await expect(
        accessControl.anyFunction({
          publicKey: account1.publicKey,
          signature: account1.payload.response.signature,
          clientDataJSON: account1.payload.response.clientDataJSON,
          authenticatorData: account1.payload.response.authenticatorData,
        }),
      )
        .to.be.revertedWithCustomError(accessControl, 'AccessControlUnauthorizedAccount')
        .withArgs(account1.publicKey, await accessControl.ANY_ROLE());
    });

    it('should call function if user has rights', async () => {
      const { accessControl } = await loadFixture(deployFixture);

      await (
        await accessControl.grantRole(
          {
            publicKey: admin.publicKey,
            signature: admin.payload.response.signature,
            clientDataJSON: admin.payload.response.clientDataJSON,
            authenticatorData: admin.payload.response.authenticatorData,
          },
          await accessControl.ANY_ROLE(),
          account1.publicKey,
        )
      ).wait();

      const response = await (
        await accessControl.anyFunction({
          publicKey: account1.publicKey,
          signature: account1.payload.response.signature,
          clientDataJSON: account1.payload.response.clientDataJSON,
          authenticatorData: account1.payload.response.authenticatorData,
        })
      ).wait();

      expect(response).to.not.be.undefined;
    });
  });
});
