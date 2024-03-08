import { useMemo, useState } from 'react';
import { ethers } from 'ethers';
import { ERC721AccountFactory__factory, GenericERC721__factory } from '@giano/contracts/typechain-types';
import { decode as cborDecode } from 'cbor-web';
import { parseAuthenticatorData } from '@simplewebauthn/server/helpers';

const ERC721AccountClient: React.FC = () => {

  const provider = useMemo(() => new ethers.WebSocketProvider('ws://localhost:8545'), []);
  const signer = useMemo(() => new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider), [provider]);
  const accountFactory = useMemo(() => ERC721AccountFactory__factory.connect('0x5fbdb2315678afecb367f032d93f642f64180aa3', signer), [signer]);
  const tokenContract = useMemo(() => GenericERC721__factory.connect('0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', signer), [signer])

  const [username, setUsername] = useState('');

  const mint = async (e) => {
    const credential = await window.navigator.credentials.get({
      publicKey: {
        challenge: new TextEncoder().encode('abc'),
        rpId: window.location.hostname,
        userVerification: 'preferred'
      }
    }) as PublicKeyCredential & { response: AuthenticatorAssertionResponse }
    const user = await accountFactory.getUser(new Uint8Array(credential.rawId).join(''))

    await tokenContract.mint(user.account);
  };


  const createUser = async (e) => {
    e.preventDefault();
    console.log({ username });
    const credential = await navigator.credentials.create(
      {
        publicKey: {
          challenge: new TextEncoder().encode('abc'),
          authenticatorSelection: {
            requireResidentKey: true,
            userVerification: 'required',
            authenticatorAttachment: 'platform'
          },
          rp: {
            id: window.location.hostname,
            name: 'Giano'
          },
          user: {
            id: new TextEncoder().encode(username),
            displayName: username,
            name: username,
          },
          pubKeyCredParams: [
            {
              alg: -7,
              type: 'public-key'
            },
            {
              alg: -257,
              type: 'public-key'
            }
          ],
          timeout: 60_000,
        }
      }
    ) as PublicKeyCredential & { response: AuthenticatorAttestationResponse }

    const attestation = cborDecode(new Uint8Array(credential.response.attestationObject));
    const authData = parseAuthenticatorData(attestation.authData);
    const publicKey = cborDecode(authData.credentialPublicKey?.buffer as ArrayBuffer);
    const [x, y] = [publicKey.get(-2), publicKey.get(-3)];
    const userId = new Uint8Array(credential.rawId).join('');
    await (await (accountFactory.createUser(userId, { x, y }))).wait();

  }
  return (
    <>
      <form>
        <input type="text" name="username" placeholder="Username" onChange={(e) => setUsername(e.target.value)} value={username} />
        <input type="button" value="Create Account" disabled={!username} onClick={createUser} className="btn-outline btn" />
        <input type="button" value="Mint" onClick={mint} className="btn-outline btn" />
      </form>
    </>
  );
};

export default ERC721AccountClient;