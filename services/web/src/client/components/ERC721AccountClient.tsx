import { decode } from 'cbor-web';
import { useState } from 'react';

const ERC721AccountClient: React.FC = () => {

  const [username, setUsername] = useState('');

  function extractPublicKeyFromAuthenticatorData(authenticatorData: ArrayBuffer) {
    if (authenticatorData.byteLength < 37) {
      throw new Error('Authenticator data is too short');
    }
    const key = authenticatorData.slice(37)
    console.log(authenticatorData.byteLength);
    return decode(key)
  }

  const mint = async (e) => {
    const {response} = await navigator.credentials.get({
      publicKey: {
        challenge: new TextEncoder().encode('abc'),
        rpId: window.location.hostname,
        userVerification: 'required'
      }
    }) as PublicKeyCredential
    const pubKey = extractPublicKeyFromAuthenticatorData((response as AuthenticatorAssertionResponse).authenticatorData)
    console.log({pubKey});
  };

  const createAccount = async (e) => {
    e.preventDefault();
    console.log({username});
    const { response } = await navigator.credentials.create(
      {
        publicKey: {
          challenge: new TextEncoder().encode('abc'),
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
    ) as PublicKeyCredential;
    console.log({ pubKey: (response as AuthenticatorAttestationResponse).getPublicKey() });
  };

  return (
    <>
      <form>
        <input type="text" name="username" placeholder="Username" onChange={(e) => setUsername(e.target.value)} value={username} />
        <input type="button" value="Create Account" disabled={!username} onClick={createAccount} className="btn-outline btn" />
        <input type="button" value="Mint" onClick={mint} className="btn-outline btn" />
      </form>
    </>
  );
};

export default ERC721AccountClient;