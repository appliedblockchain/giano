import React from 'react';
import * as helpers from '../../misc/helpers';
import verifyAssertion from '../../misc/verifyAssertion';

const RP_ID = window.location.hostname;
const RP_NAME = 'Passkey PoC';
const RP_ORIGINS = ['http://localhost', 'http://localhost:3000', 'https://passkey-poc.ngrok.dev'];

const AuthClient: React.FC = () => {
  const [result, setResult] = React.useState<null | string>(null);

  const onSubmit = (event) => {
    event.preventDefault();
    const action = event.nativeEvent.submitter?.name;
    const formData = Object.fromEntries(new FormData(event.target));
    const username = (formData.username as string)?.trim();
    const credentialId = (formData.credential_id as string)?.trim();
    const publicKey = (formData.public_key as string)?.trim();

    setResult(null);

    if (action === 'attestation') void attestate(username);
    else if (action === 'assertion') void assert(credentialId, publicKey);
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
    const credentialId = helpers.bufferToBase64URL(credential.rawId);

    setResult(`Credential ID:\n${credentialId}\n\nPublic key:\n${pubKey}`);
    return pubKey;
  };

  const assert = async (credentialId: undefined | string, publicKey: string) => {
    const challenge = 'abc';

    const allowCredentials = credentialId
      ? [
          {
            id: helpers.base64URLToBuffer(credentialId),
            type: 'public-key',
          },
        ]
      : undefined;

    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: new TextEncoder().encode(challenge),
        rpId: RP_ID,
        timeout: 60_000,
        allowCredentials,
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
      setResult('Signature verification failed. ❌');
      throw new Error('Signature verification failed. ❌');
    } else {
      console.log('Signature verification succeeded! 🎉');
      setResult('Signature verification succeeded! 🎉');
    }
  };

  return (
    <>
      <main className="m-auto mt-14 flex w-[600px] flex-row flex-wrap justify-between gap-4">
        <h1 className="w-full grow basis-full text-2xl">Passkey PoC</h1>
        <hr className="mb-4 w-full grow basis-full" />

        <section className="paper">
          <form className="flex flex-col gap-4" onSubmit={onSubmit}>
            <h2 className="text-base">Register (Attestation)</h2>

            <div className="form-control w-full max-w-xs">
              <label className="label">
                <span className="label-text">Username</span>
              </label>
              <input name="username" type="text" placeholder="New username" className="input input-bordered w-full max-w-xs" required={true} />
            </div>

            <div className="flex flex-row justify-between gap-4">
              <button name={'attestation'} className="btn btn-outline">
                Create passkey
              </button>
            </div>
          </form>
        </section>

        <section className="paper">
          <form className="flex flex-col gap-4" onSubmit={onSubmit}>
            <h2 className="text-base">Login (Assertion)</h2>

            <div className="form-control w-full max-w-xs">
              <label className="label">
                <span className="label-text">Credential ID</span>
              </label>
              <input name="credential_id" type="text" placeholder="Credential ID generated" className="input input-bordered w-full max-w-xs" />
            </div>

            <div className="form-control w-full max-w-xs">
              <label className="label">
                <span className="label-text">Public Key*</span>
              </label>
              <input name="public_key" type="text" placeholder="Public Key generated" className="input input-bordered w-full max-w-xs" required={true} />
            </div>

            <div className="flex flex-row justify-between gap-4">
              <button name={'assertion'} className="btn btn-outline">
                Sign with passkey
              </button>
            </div>
          </form>
        </section>
      </main>
      {result !== null && (
        <p className="mx-auto mt-12 flex max-w-[400px] flex-col items-center gap-4 whitespace-pre-wrap break-all text-lg font-bold">{result}</p>
      )}
    </>
  );
};

export default AuthClient;
