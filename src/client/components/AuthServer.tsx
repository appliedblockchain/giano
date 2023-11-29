import React from 'react';
import { FaCopy as ICopy } from 'react-icons/fa';
import * as helpers from '../../misc/helpers';

const AuthServer: React.FC = () => {
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
    else if (action === 'assertion') void assert(username);
    else window.alert('Choose an action between "Create" and "Sign"');
  };

  const attestate = async (username: string) => {
    try {
      const options = await helpers.fetchPost('/api/register/start', { username });

      options.challenge = new TextEncoder().encode(options.challenge);
      options.user.id = new TextEncoder().encode(options.user.id);
      options.user.username = new TextEncoder().encode(options.user.username);

      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) return;
      const attestationResponse = credential.response as AuthenticatorAttestationResponse;

      const payload = {
        username,
        id: credential.id,
        publicKey: helpers.bufferToBase64URL(attestationResponse.getPublicKey()),
        coseAlg: attestationResponse.getPublicKeyAlgorithm(),
        clientDataJSON: helpers.bufferToBase64URL(attestationResponse.clientDataJSON),
        attestationObject: helpers.bufferToBase64URL(attestationResponse.attestationObject),
        transports: attestationResponse.getTransports(),
      };

      await helpers.fetchPost('/api/register/complete', payload);

      const pubKey = payload.publicKey;
      setPubKey(pubKey);
      setResult(`Public key:\n${pubKey}`);
    } catch (error) {
      console.error(error);
      setResult(`Error: ` + (error as Error).message);
    }
  };

  const assert = async (username: string) => {
    const options = await helpers.fetchPost('/api/login/start', { username });

    options.challenge = new TextEncoder().encode(options.challenge);
    options.allowCredentials = options.allowCredentials?.map((credential) => ({
      ...credential,
      id: helpers.base64URLToBuffer(credential.id),
    }));

    const credential = await navigator.credentials.get({
      publicKey: options,
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

    try {
      await helpers.fetchPost('/api/login/complete', { username, ...payload });
      setResult('Signature verification succeeded! 🎉');
    } catch (error) {
      console.error(error);
      setResult('Signature verification failed.');
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
            <input name="username" type="text" placeholder="Type here" className="input input-bordered w-full max-w-xs" defaultValue="bruce.wayne" />
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

export default AuthServer;
