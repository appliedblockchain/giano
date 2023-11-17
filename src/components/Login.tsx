import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import * as base64url from '@cfworker/base64url';
import { startAuthentication } from '@simplewebauthn/browser';
import { Buffer } from 'buffer';
import { WebAuthnController } from 'oslo/webauthn';
import { areBytewiseEqual, base64URLToBuffer, byteStringToBuffer, fetchPost } from '../helpers';
import * as helpers from '../helpers';

const PUBLIC_KEY = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4dsfSF7G2EhzwIjScc2QtPwMZVFGz5owFAlkwy_QX1TK9W-Swih-Teao3CjWP5sLcHjoi82hgBhq52k8tv3xEw';

const Login: React.FC = () => {
  const [result, setResult] = React.useState<null | string>(null);
  const navigate = useNavigate();

  const onSubmit = async (event) => {
    event.preventDefault();
    const formData = Object.fromEntries(new FormData(event.target));
    const username = formData.username as string;

    try {
      const loginOptions = await fetchPost('/api/login/start', { username });
      const attestationResponse = await startAuthentication(loginOptions);
      const loginResult = await fetchPost('/api/login/complete', { username, ...attestationResponse });
      console.log(loginResult);

      if (true) {
        const oslo = new WebAuthnController(window.location.href);
        const publicKey = base64URLToBuffer(PUBLIC_KEY);
        const challenge = JSON.parse(base64url.decode(attestationResponse.response.clientDataJSON)).challenge;
        const attResponse = {
          clientDataJSON: JSON.parse(base64url.decode(attestationResponse.response.clientDataJSON)),
          authenticatorData: base64URLToBuffer(attestationResponse.response.authenticatorData),
          signature: base64URLToBuffer(attestationResponse.response.signature),
        };
        const result = await oslo.validateAssertionResponse('ES256', publicKey, attResponse, challenge);
        console.log('result', result);
      } else if (false) {
        const publicKey = base64URLToBuffer(PUBLIC_KEY);

        const response = attestationResponse.response;

        const clientData = JSON.parse(base64url.decode(response.clientDataJSON)) as {
          type: string; // 'webauthn.get' or 'webauthn.create'
          challenge: string; // base64url encoded challenge
          origin: string; // url origin
        };

        if (clientData.type !== 'webauthn.get') throw new Error("Failed to verify 'clientData.type'");
        if (clientData.origin !== window.location.origin) throw new Error("Failed to verify 'clientData.origin");

        const authData = new Uint8Array(base64URLToBuffer(response.authenticatorData));
        if (authData.byteLength < 37) throw new Error("Malformed 'authData'");

        const rpIdHash = authData.slice(0, 32);
        const rpIdData = new TextEncoder().encode(window.location.hostname);
        const expectedRpIdHash = await crypto.subtle.digest('SHA-256', rpIdData);
        if (!areBytewiseEqual(rpIdHash, expectedRpIdHash)) throw new Error("Failed to verify 'rpId' hash");

        const flagsBits = authData[32].toString(2);
        if (flagsBits.charAt(flagsBits.length - 1) !== '1') throw new Error('Failed to verify user present flag');

        // the signature is encoded in DER thus we need to convert into ECDSA compatible format
        const signature = helpers.convertDERSignatureToECDSASignature(base64URLToBuffer(response.signature));
        const hash = await crypto.subtle.digest('SHA-256', Buffer.from(response.clientDataJSON, 'utf-8'));
        console.log(hash);

        const data = helpers.concatenateBuffers(authData, new Uint8Array(hash));

        const verifiedSignature = await crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: 'SHA-256',
          },
          await crypto.subtle.importKey(
            'spki',
            publicKey,
            {
              name: 'ECDSA',
              namedCurve: 'P-256',
            },
            true,
            ['verify'],
          ),
          signature,
          data,
        );

        if (!verifiedSignature) throw new Error('Failed to verify signature');
      } else {
        // verify signature client-side
        const signature = byteStringToBuffer(attestationResponse.response.signature);
        const clientDataJSON = base64URLToBuffer(attestationResponse.response.clientDataJSON);
        const authenticatorData = base64URLToBuffer(attestationResponse.response.authenticatorData);
        const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));

        // concat authenticatorData and clientDataHash
        const signedData = new Uint8Array(authenticatorData.length + clientDataHash.byteLength);
        signedData.set(authenticatorData);
        signedData.set(clientDataHash, authenticatorData.length);

        // import key
        const key = await crypto.subtle.importKey(
          'spki',
          base64URLToBuffer(PUBLIC_KEY),
          {
            name: 'ECDSA',
            namedCurve: 'P-256',
            hash: { name: 'SHA-256' },
          },
          false,
          ['verify'],
        );

        // check signature with public key and signed data
        const verified = await crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-256' } }, key, signature, signedData.buffer);
        console.log('verified', verified);

        if (!verified) throw new Error('Signature verification failed');
      }

      setResult('Success!');
      setTimeout(() => navigate('/home'), 1500);
    } catch (error) {
      console.error(error);
      setResult((error as Error).message);
    }
  };

  console.log(result);

  return (
    <main className="paper m-auto mt-14 w-max">
      <h2 className="mb-4 text-2xl">Login</h2>
      <form className="flex flex-col gap-4" onSubmit={onSubmit}>
        <div className="form-control w-full max-w-xs">
          <label className="label">
            <span className="label-text">Username</span>
          </label>
          <input name="username" type="text" placeholder="Type here" className="input input-bordered w-full max-w-xs" defaultValue="bruce.wayne" />
        </div>

        <button className="btn w-min">Login</button>
      </form>

      <p className="text-sm">
        <span>Not registered yet? Go to </span>
        <NavLink className="link-primary link" to={'/register'}>
          register page.
        </NavLink>
      </p>

      {result !== null && <h2 className="mt-10 w-min text-lg font-bold">{result}</h2>}
    </main>
  );
};

export default Login;
