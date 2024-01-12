import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';
import { expect } from 'chai';
import hardhat from 'hardhat';
const { ethers } = hardhat;
import type { Log } from 'ethers';
import * as asn1 from '../src/misc/asn1';
import * as helpers from '../src/misc/helpers';
import { parseLog } from './utils';

// We define a fixture to reuse the same setup in every test: we use loadFixture to run this setup once, snapshot that state, and reset Hardhat Network to that snapshot in every test.
async function deployFixture() {
  const [ownerAccount, account] = await ethers.getSigners();
  const PassKey = await ethers.getContractFactory('PassKey');
  const passkey = await PassKey.deploy();
  return { passkey, ownerAccount, account };
}

describe('PassKey', () => {
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

      const response = await (await passkey.parseAndVerifyPassKeySignature({ publicKey, signature, authenticatorData, clientDataJSON })).wait();

      const log = parseLog(response?.logs[0] as Log);
      expect(log.fragment.name).to.equal('SignatureVerified');
      expect(log.args[0]).to.equal(ethers.solidityPackedKeccak256(['string'], [publicKey]));
      expect(log.args[1]).to.equal(ethers.solidityPackedKeccak256(['string'], [signature]));
      expect(log.args[2]).to.equal(true);
    });

    it('should false if signature is invalid', async () => {
      const { passkey } = await loadFixture(deployFixture);

      const publicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5jCn87rbZZDLc8VHJ8dxAs4hx95Y1n0__U_I8qvwG6UytkNz9Dx7WjlEDWx_fj5IjGnFKC1KN-DOVKIMRGy-oQ';

      const payload = {
        id: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        rawId: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWVdKaiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
          authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
          signature: 'MEUCIQDNbZxz5Re-Yo9FS7xa4LyXYlAKe9-VQ1umIz4rIAacLgIgZenp4ijLbKoRBQ7nR0pTBwrNf2QTsqSgFZtThgX3oeU',
        },
      };

      const signature = payload.response.signature;
      const authenticatorData = payload.response.authenticatorData;
      const clientDataJSON = payload.response.clientDataJSON;

      const response = await (await passkey.parseAndVerifyPassKeySignature({ publicKey, signature, authenticatorData, clientDataJSON })).wait();

      const log = parseLog(response?.logs[0] as Log);
      expect(log.fragment.name).to.equal('SignatureVerified');
      expect(log.args[0]).to.equal(ethers.solidityPackedKeccak256(['string'], [publicKey]));
      expect(log.args[1]).to.equal(ethers.solidityPackedKeccak256(['string'], [signature]));
      expect(log.args[2]).to.equal(false);
    });

    it('should revert if public key format is invalid', async () => {
      const { passkey } = await loadFixture(deployFixture);

      const publicKey = Buffer.from('incorrect_public_key').toString('base64');

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

      await expect(passkey.parseAndVerifyPassKeySignature({ publicKey, signature, authenticatorData, clientDataJSON })).to.be.revertedWithCustomError(
        passkey,
        'InvalidFormat',
      );
    });

    it('should revert if signature format is invalid', async () => {
      const { passkey } = await loadFixture(deployFixture);

      const publicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5jCn87rbZZDLc8VHJ8dxAs4hx95Y1n0__U_I8qvwG6UytkNz9Dx7WjlEDWx_fj5IjGnFKC1KN-DOVKIMRGy-oQ';

      const payload = {
        id: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        rawId: 'ZlrAhA3QjT7IJwYZceyfjA_e5vo',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWVdKaiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
          authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
          signature: Buffer.from('incorrect_signature').toString('base64'),
        },
      };

      const signature = payload.response.signature;
      const authenticatorData = payload.response.authenticatorData;
      const clientDataJSON = payload.response.clientDataJSON;

      await expect(passkey.parseAndVerifyPassKeySignature({ publicKey, signature, authenticatorData, clientDataJSON })).to.be.revertedWithCustomError(
        passkey,
        'InvalidFormat',
      );
    });

    it('should revert if signature was already used', async () => {
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

      await (await passkey.parseAndVerifyPassKeySignature({ publicKey, signature, authenticatorData, clientDataJSON })).wait();
      await expect(passkey.parseAndVerifyPassKeySignature({ publicKey, signature, authenticatorData, clientDataJSON }))
        .to.be.revertedWithCustomError(passkey, 'InvalidSignature')
        .withArgs(publicKey, signature);
    });
  });
});
