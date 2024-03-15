import { useMemo, useState } from 'react';
import { ethers } from 'ethers';
import {
  ERC721Account__factory,
  ERC721AccountFactory__factory,
  GenericERC721__factory
} from '@giano/contracts/typechain-types';
import { decode as cborDecode } from 'cbor-web';
import { parseAuthenticatorData } from '@simplewebauthn/server/helpers';
import { AsnParser } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';

const ERC721AccountClient: React.FC = () => {

  type User = {
    account: string;
    rawId: BufferSource;
    credentialId: bigint;
  }

  const provider = useMemo(() => new ethers.WebSocketProvider('ws://localhost:8545'), []);
  const signer = useMemo(() => new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider), [provider]);
  const accountFactory = useMemo(() => ERC721AccountFactory__factory.connect('0x5fbdb2315678afecb367f032d93f642f64180aa3', signer), [signer]);
  const tokenContract = useMemo(() => GenericERC721__factory.connect('0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', signer), [signer])

  const [username, setUsername] = useState('');
  const [recipient, setRecipient] = useState('');
  const [tokenId, setTokenId] = useState('');
  const [status, setStatus] = useState('');
  const [user, setUser] = useState(null as User | null);

  const uint8ArrayToUint256 = (array: ArrayBuffer) => {
    const arr = new Uint8Array(array)
    let result = 0n

    for (let i = 0; i < arr.length; i++) {
      result = (result << 8n) + BigInt(arr[i])
    }

    return result
  };

  const getCredential = async (id?: BufferSource, challenge?: BufferSource) => {
    return await window.navigator.credentials.get({
      publicKey: {
        challenge: challenge || new TextEncoder().encode(''),
        rpId: window.location.hostname,
        userVerification: 'preferred',
        ...id && {
          allowCredentials: [
            {
              id: id,
              type: 'public-key'
            }
          ]
        }
      }
    }) as PublicKeyCredential & { response: AuthenticatorAssertionResponse }
  };

  const mint = async () => {
    if (user) {
      await tokenContract.mint(user.account);
    }
  };

  const logIn = async () => {
    const credential = await getCredential();
    const userId = uint8ArrayToUint256 (credential.rawId);
    if (credential) {
      const user = await accountFactory.getUser(userId);
      if (user.account !== ethers.ZeroAddress) {
        setUser({
          account: user.account,
          rawId: credential.rawId,
          credentialId: userId
        });
      }
    }
  };

  const hexToUint8Array = (hex: string) => {
    if (hex.startsWith('0x')) {
      hex = hex.slice(2);
    }
    return new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
  };

  const createUser = async (e) => {
    e.preventDefault();
    console.log({ username });
    setStatus('Creating user...');
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

    try {
      const attestation = cborDecode(new Uint8Array(credential.response.attestationObject));
      const authData = parseAuthenticatorData(attestation.authData);
      const publicKey = cborDecode(authData.credentialPublicKey?.buffer as ArrayBuffer);
      const [x, y] = [publicKey.get(-2), publicKey.get(-3)];
      const userId = uint8ArrayToUint256 (credential.rawId);
      await (await (accountFactory.createUser(userId, { x, y }))).wait();
    } catch (e) {
      console.error(e);
      setStatus('Error creating user, check the console');
    }
    setStatus('User created!');
  }

  const transfer = async () => {
    if (!user) {
      throw new Error('Not logged in');
    }
    const accountContract = ERC721Account__factory.connect(user.account, signer);
    const challengeHex = await accountContract.getChallenge();
    const challenge = hexToUint8Array(challengeHex);

    const credential = await getCredential(user.rawId, challenge);

    const parsedSignature = AsnParser.parse(credential.response.signature, ECDSASigValue);

    const clientDataJson = new TextDecoder().decode(credential.response.clientDataJSON);
    const responseTypeLocation = clientDataJson.indexOf('"type":');
    const challengeLocation = clientDataJson.indexOf('"challenge":');
    const signature = ethers.AbiCoder.defaultAbiCoder().encode(
      ['tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeLocation, uint256 responseTypeLocation, uint256 r, uint256 s)'],
      [[new Uint8Array(credential.response.authenticatorData), clientDataJson, challengeLocation, responseTypeLocation, uint8ArrayToUint256(parsedSignature.r), uint8ArrayToUint256(parsedSignature.s)]]
    );
    await accountContract.transferToken(tokenContract.target, recipient, tokenId,  signature);
  };

  return (
    <>
      <main className={'p-5 mx-auto w-1/2'}>
        <section>
          <h2 className={'text-xl font-bold'}>Create account</h2>
          <form>
            <input type="text" name="username" placeholder="Username" onChange={(e) => setUsername(e.target.value)}
                   value={username} />
            <input type="button" value="Create Account" disabled={!username} onClick={createUser}
                   className="btn-outline btn" />
          </form>
        </section>
        <section>
          <h2 className={'text-xl font-bold'}>Log in</h2>
          <form>
            <input type="button" value="Log in" onClick={logIn}
                   className="btn-outline btn" />
          </form>
          <p>
            {user ? `Logged in as ${user.account}` : 'Not logged in'}
          </p>
        </section>
        <section>
          <h2 className={'text-xl font-bold'}>Mint</h2>
          <form>
            <input type="button" value="Mint" onClick={mint} className="btn-outline btn" />
          </form>
        </section>
        <section>
          <h2 className={'text-xl font-bold'}>Transfer token</h2>
          <form>
            <input type="text" name="recipient" placeholder="Recipient" onChange={(e) => setRecipient(e.target.value)}
                   value={recipient} />
            <input type="number" name="tokenId" placeholder="Token ID" onChange={(e) => setTokenId(e.target.value)}
                   value={tokenId} />
            <input type="button" value="Transfer" onClick={transfer} className="btn-outline btn" />
          </form>
        </section>
        <section>
          {status}
        </section>
      </main>
    </>
  );
};

export default ERC721AccountClient;