import { useEffect, useState } from 'react';
import type { WalletConfig } from '../config';
import type { WalletRuntime } from '../wallet';

type Me = { externalUserId: string; walletAddress: string; credentialId: string };
type Credential = { credentialId: string; walletAddress: string; createdAt: string };

/** Standalone view when the wallet page is opened directly (not via a dApp popup). */
export function Settings({ runtime, config }: { runtime: WalletRuntime; config: WalletConfig }) {
  const [me, setMe] = useState<Me | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const token = runtime.injection.getSessionToken();

  const load = async () => {
    if (!token) return;
    try {
      const headers = { authorization: `Bearer ${token}` };
      const base = config.walletApiUrl.replace(/\/$/, '');
      const [meRes, credsRes] = await Promise.all([
        fetch(`${base}/v1/me`, { headers }),
        fetch(`${base}/v1/me/credentials`, { headers }),
      ]);
      if (meRes.ok) setMe((await meRes.json()) as Me);
      if (credsRes.ok) setCredentials(((await credsRes.json()) as { credentials: Credential[] }).credentials);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const signIn = async () => {
    setBusy(true);
    setError(null);
    try {
      await runtime.provider.request({ method: 'eth_requestAccounts' });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const logout = async () => {
    setBusy(true);
    try {
      await runtime.injection.logout();
      setMe(null);
      setCredentials([]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="card">
        <h2>Wallet</h2>
        {me ? (
          <>
            <div className="kv">
              <span className="k">Address</span>
              <span className="v">{me.walletAddress}</span>
            </div>
            <div className="kv">
              <span className="k">Chain</span>
              <span className="v">{runtime.chainId}</span>
            </div>
          </>
        ) : (
          <p>{token ? 'Loading session…' : 'No active session on this device.'}</p>
        )}
        {error ? <div className="error">{error}</div> : null}
      </div>

      {me ? (
        <div className="card">
          <h2>Passkeys</h2>
          {credentials.map((credential) => (
            <div className="kv" key={credential.credentialId}>
              <span className="k">{new Date(credential.createdAt).toLocaleDateString()}</span>
              <span className="v">{credential.credentialId.slice(0, 12)}…</span>
            </div>
          ))}
          {credentials.length === 0 ? <p>No passkeys registered.</p> : null}
        </div>
      ) : null}

      <div className="actions">
        {me ? (
          <button className="danger" onClick={logout} disabled={busy}>
            Log out (revoke session)
          </button>
        ) : (
          <button className="primary" onClick={signIn} disabled={busy}>
            {busy ? 'Waiting for passkey…' : 'Sign in with passkey'}
          </button>
        )}
      </div>
    </>
  );
}
