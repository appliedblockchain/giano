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
    it('should validate passkey signature', async () => {
      const { passkey } = await loadFixture(deployFixture);

      const derPublicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5jCn87rbZZDLc8VHJ8dxAs4hx95Y1n0__U_I8qvwG6UytkNz9Dx7WjlEDWx_fj5IjGnFKC1KN-DOVKIMRGy-oQ';
      const [pubKeyX, pubKeyY] = asn1.parsePublicKey(derPublicKey);

      const payload = {
        id: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        rawId: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWVdKaiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
          authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
          signature: 'MEUCIGT47yTmzNsYrwkpdqptRTOJmBjhbcLK_tSpA8mosbVSAiEAjRCIERiV7EMvI37tDgYQp-EwhDnlba7fKsW4aDvWGMg',
        },
      };

      const [sigX, sigY] = asn1.parseSignature(payload.response.signature);

      const authenticatorData = Buffer.from(payload.response.authenticatorData, 'base64');
      const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from(payload.response.clientDataJSON, 'base64')));
      const data = new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.concat([authenticatorData, clientDataHash])));

      const response = await passkey.verifyPassKeySignature(
        helpers.bufferToBigInt(pubKeyX),
        helpers.bufferToBigInt(pubKeyY),
        helpers.bufferToBigInt(sigX),
        helpers.bufferToBigInt(sigY),
        helpers.bufferToBigInt(data),
      );
      expect(response).to.equal(true);
    });
  });
});
