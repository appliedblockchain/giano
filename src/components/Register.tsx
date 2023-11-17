import React from 'react';
import { NavLink } from 'react-router-dom';
import { startRegistration } from '@simplewebauthn/browser';
import { Buffer } from 'buffer';
import * as cbor from 'cbor-web';
import { fetchPost } from '../helpers';

const Register: React.FC = () => {
  const [result, setResult] = React.useState<null | string>(null);

  const onSubmit = async (event) => {
    event.preventDefault();
    const formData = Object.fromEntries(new FormData(event.target));
    const username = formData.username as string;

    try {
      const registrationOptions = await fetchPost('/api/register/start', { username });
      const attestationResponse = await startRegistration(registrationOptions);
      const registrationResult = await fetchPost('/api/register/complete', { username, ...attestationResponse });
      console.log(attestationResponse, registrationResult);

      const publicKey = attestationResponse.response.publicKey;

      setResult(`Success! PubKey is ${publicKey}`);
    } catch (error) {
      setResult((error as Error).message);
    }
  };

  console.log(result);

  return (
    <main className="paper m-auto mt-14 w-max">
      <h2 className="mb-4 text-2xl">Register</h2>
      <form className="flex flex-col gap-4" onSubmit={onSubmit}>
        <div className="form-control w-full max-w-xs">
          <label className="label">
            <span className="label-text">Username</span>
          </label>
          <input name="username" type="text" placeholder="Type here" className="input input-bordered w-full max-w-xs" defaultValue="bruce.wayne" />
        </div>

        <button className="btn w-min">Register</button>
      </form>

      <p className="text-sm">
        <span>Already registered? Go to </span>
        <NavLink className="link-primary link" to={'/login'}>
          login page.
        </NavLink>
      </p>

      {result !== null && <h2 className="mt-10 w-min text-lg font-bold">{result}</h2>}
    </main>
  );
};

export default Register;
