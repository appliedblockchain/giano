import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import hardhat from 'hardhat';
const { ethers } = hardhat;
import * as asn1 from '../src/misc/asn1';
import * as helpers from '../src/misc/helpers';

// We define a fixture to reuse the same setup in every test: we use loadFixture to run this setup once, snapshot that state, and reset Hardhat Network to that snapshot in every test.
async function deployFixture() {
  const [ownerAccount, account] = await ethers.getSigners();
  const PassKey = await ethers.getContractFactory('PassKey');
  const passkey = await PassKey.deploy();
  return { passkey, ownerAccount, account };
}

describe('PassKey', () => {
  describe('Deployment', () => {
    it('should set the right owner', async () => {
      const { passkey, ownerAccount } = await loadFixture(deployFixture);
      const result = await passkey.owner();
      const expected = ownerAccount.address;
      expect(result).to.equal(expected);
    });
  });

  describe('Use cases', () => {
    it('should parse and validate passkey signature', async () => {
      const { passkey } = await loadFixture(deployFixture);

      const publicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5jCn87rbZZDLc8VHJ8dxAs4hx95Y1n0__U_I8qvwG6UytkNz9Dx7WjlEDWx_fj5IjGnFKC1KN-DOVKIMRGy-oQ';

      const payload = {
        id: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        rawId: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWVdKaiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
          authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
          signature: 'MEUCIGT47yTmzNsYrwkpdqptRTOJmBjhbcLK_tSpA8mosbVSAiEAjRCIERiV7EMvI37tDgYQp-EwhDnlba7fKsW4aDvWGMg',
        },
      };

      const signature = payload.response.signature;
      const authenticatorData = payload.response.authenticatorData;
      const clientDataJSON = payload.response.clientDataJSON;

      const response = await passkey.parseAndVerifyPassKeySignature(publicKey, signature, authenticatorData, clientDataJSON);
      expect(response).to.equal(true);
    });
  });
});
