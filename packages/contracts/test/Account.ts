import { expect } from 'chai';
import { ethers, ignition } from 'hardhat';
import { Account } from '../typechain-types';
import { createKeypair } from './utils';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import crypto from 'crypto';
import GianoModule from '../ignition/modules/Giano';
import { loadFixture } from '@nomicfoundation/hardhat-toolbox/network-helpers';

describe('Account Contract', () => {
  let account: Account;
  let genericERC20: any;
  let signer: any;
  let otherSigner: any;
  let publicKey: any;
  let keypair: any;

  const deployFixture = async () => {
    const [signer, otherSigner] = await ethers.getSigners();
    const { erc20, erc721, accountFactory } = await ignition.deploy(GianoModule);

    return { signer, otherSigner, erc20, erc721, accountFactory };
  };

  beforeEach(async () => {
    ({ signer, otherSigner, erc20: genericERC20 } = await loadFixture(deployFixture));

    // Create keypair and deploy Account
    keypair = createKeypair();
    publicKey = {
      x: keypair.x,
      y: keypair.y,
    };

    const AccountFactory = await ethers.getContractFactory('Account', signer);
    account = await AccountFactory.deploy(publicKey);
    await account.waitForDeployment();
  });

  describe('execute', () => {
    it.only('should execute a transfer on GenericERC20 token', async () => {
      // Mint tokens to account
      await genericERC20.transfer(account.target, ethers.parseEther('100'));

      // Prepare call data for transfer
      const recipient = otherSigner.address;
      const amount = ethers.parseEther('10');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);

      // Generate a valid signature
      const challenge = await account.getChallenge();
      const signature = await signChallenge(keypair.keyPair.privateKey, hexToUint8Array(challenge));

      // Execute transfer via Account contract
      await expect(
        account.execute({
          target: genericERC20.target,
          value: 0,
          data: transferData,
          signature: encodeChallenge(signature),
        }),
      )
        .to.emit(genericERC20, 'Transfer')
        .withArgs(account.target, recipient, amount);

      // Check recipient balance
      const balance = await genericERC20.balanceOf(recipient);
      expect(balance).to.equal(amount);
    });

    it('should revert with InvalidSignature for incorrect signature', async () => {
      // Prepare call data for transfer
      const recipient = otherSigner.address;
      const amount = ethers.parseEther('10');
      const transferData = genericERC20.interface.encodeFunctionData('transfer', [recipient, amount]);

      // Generate an invalid signature (e.g., random bytes)
      const invalidSignature = crypto.randomBytes(130); // 65 bytes for ECDSA

      // Attempt to execute transfer via Account contract
      await expect(
        account.execute({
          target: genericERC20.target,
          value: 0,
          data: transferData,
          signature: invalidSignature,
        }),
      ).to.be.revertedWith('InvalidSignature');
    });
  });
});

function hexToUint8Array(hex: string) {
  if (hex.startsWith('0x')) {
    hex = hex.slice(2);
  }
  return new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
}

function uint8ArrayToUint256(array: ArrayBuffer) {
  const hex = Array.from(new Uint8Array(array))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return BigInt('0x' + hex);
}

function signChallenge(privateKey: crypto.KeyObject, challenge: Uint8Array) {
  // Step 2: Prepare clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: Buffer.from(challenge).toString('base64url'),
    origin: 'https://localhost:3000',
    crossOrigin: false,
  };
  const clientDataJSON = Buffer.from(JSON.stringify(clientData));

  // Step 3: Hash the clientDataJSON
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();

  // Step 4: Prepare authenticatorData
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  const flags = Buffer.from([0x01]); // User Present flag
  const signCount = Buffer.alloc(4); // 32-bit signature counter
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCount]);

  // Step 5: Concatenate authenticatorData and clientDataHash
  const dataToSign = Buffer.concat([authenticatorData, clientDataHash]);

  // Step 6: Sign the concatenated data
  const signature = crypto.createSign('SHA256').update(dataToSign).sign(privateKey);

  // Step 7: Assemble the response
  return {
    clientDataJSON: clientDataJSON,
    authenticatorData: authenticatorData,
    signature: signature,
  };
}

function encodeChallenge(assertionResponse: any) {
  const decodedClientDataJson = new TextDecoder().decode(assertionResponse.clientDataJSON);
  const responseTypeLocation = decodedClientDataJson.indexOf('"type":');
  const challengeLocation = decodedClientDataJson.indexOf('"challenge":');
  const parsedSignature = AsnParser.parse(assertionResponse.signature, ECDSASigValue);

  return ethers.AbiCoder.defaultAbiCoder().encode(
    ['tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeLocation, uint256 responseTypeLocation, uint256 r, uint256 s)'],
    [
      [
        new Uint8Array(assertionResponse.authenticatorData),
        decodedClientDataJson,
        challengeLocation,
        responseTypeLocation,
        uint8ArrayToUint256(parsedSignature.r),
        uint8ArrayToUint256(parsedSignature.s),
      ],
    ],
  );
}
