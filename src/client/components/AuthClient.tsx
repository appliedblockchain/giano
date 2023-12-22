import React from 'react';
import { FaCopy as ICopy } from 'react-icons/fa';
import * as helpers from '../../misc/helpers';
import verifyAssertion from '../../misc/verifyAssertion';

const RP_ID = window.location.hostname;
const RP_NAME = 'WebAuthn PoC';
const RP_ORIGINS = ['http://localhost', 'http://localhost:3000', 'https://webauthn-poc.ngrok.dev'];

const AuthClient: React.FC = () => {
  const [result, setResult] = React.useState<null | string>(null);
  const [pubKey, setPubKey] = React.useState<null | string>(null);

  const copyPubKey = async () => {
    await navigator.clipboard.writeText(pubKey);
    alert('Public key was copied to clipboard');
  };

  const onSubmit = (event) => {
    event.preventDefault();
    const action = event.nativeEvent.submitter?.name;
    const formData = Object.fromEntries(new FormData(event.target));
    const username = formData.username as string;

    setResult(null);
    setPubKey(null);

    if (action === 'attestation') void attestate(username);
    else if (action === 'assertion') void assert();
    else window.alert('Choose an action between "Create" and "Sign"');
  };

  const attestate = async (username: string) => {
    const challenge = new TextEncoder().encode('abc');

    const options = {
      challenge,
      rp: {
        id: RP_ID,
        name: RP_NAME,
      },
      user: {
        id: new TextEncoder().encode(username),
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [
        {
          alg: -7,
          type: 'public-key',
        },
        {
          alg: -257,
          type: 'public-key',
        },
      ],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
        authenticatorAttachment: 'platform',
      },
      attestation: 'none',
      timeout: 60_000,
      extensions: {
        credProps: true,
      },
    };

    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) return;
    const attestationResponse = credential.response as AuthenticatorAttestationResponse;

    const payload = {
      kid: credential.id,
      clientDataJSON: attestationResponse.clientDataJSON,
      attestationObject: attestationResponse.attestationObject,
      pubkey: attestationResponse.getPublicKey(),
      coseAlg: attestationResponse.getPublicKeyAlgorithm(),
    };

    // todo: here you should verify attestation on the server despite not being truly needed
    const pubKey = helpers.bufferToBase64URL(payload.pubkey);
    setPubKey(pubKey);
    setResult(`Public key:\n${pubKey}`);
    return pubKey;
  };

  const assert = async () => {
    const publicKey = window.prompt('Public key:');
    if (!publicKey) return window.alert('Public key must be provided.');

    const challenge = 'abc';

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: new TextEncoder().encode(challenge),
        rpId: RP_ID,
        timeout: 60_000,
        // todo: add allowCredentials to narrow authenticator to registered one (ref: https://www.w3.org/TR/webauthn/#sctn-usecase-authentication)
      },
      mediation: 'optional',
    });

    const assertionResponse = credential.response as AuthenticatorAssertionResponse;

    const payload = {
      id: credential.id,
      rawId: helpers.bufferToBase64URL(credential.rawId),
      response: {
        clientDataJSON: helpers.bufferToBase64URL(assertionResponse.clientDataJSON),
        authenticatorData: helpers.bufferToBase64URL(assertionResponse.authenticatorData),
        signature: helpers.bufferToBase64URL(assertionResponse.signature),
      },
    };

    console.log('Public key used:');
    console.log(JSON.stringify(publicKey, null, 2));
    console.log('Payload to verify:');
    console.log(JSON.stringify(payload, null, 2));

    const verifiedSignature = await verifyAssertion(payload, challenge, RP_ID, RP_ORIGINS, publicKey);
    if (!verifiedSignature) {
      setResult('Signature verification failed.');
      throw new Error('Signature verification failed.');
    } else {
      console.log('Signature verification succeeded! 🎉');
      setResult('Signature verification succeeded! 🎉');
    }
  };

  return (
    <>
      <main className="paper m-auto mt-14 w-max">
        <h2 className="mb-4 text-2xl">WebAuthn PoC</h2>
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <div className="form-control w-full max-w-xs">
            <label className="label">
              <span className="label-text">Username</span>
            </label>
            <input name="username" type="text" placeholder="Type here" className="input input-bordered w-full max-w-xs" defaultValue="clark.kent" />
          </div>

          <div className="flex flex-row justify-between gap-4">
            <button name={'attestation'} className="btn btn-outline w-24">
              Create
            </button>
            <button name={'assertion'} className="btn btn-outline w-24">
              Sign
            </button>
          </div>
        </form>
      </main>
      {result !== null && (
        <p className="mx-auto mt-12 flex max-w-[400px] flex-col items-center gap-4 whitespace-pre-wrap break-all text-lg font-bold">
          {result}
          {pubKey && <ICopy className="cursor-pointer" onClick={copyPubKey} size={24} />}
        </p>
      )}
    </>
  );
};

export default AuthClient;
