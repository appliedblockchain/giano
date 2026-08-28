import { useEffect, useState } from 'react';
import type { WalletConfig } from '../config';
import type { WalletRuntimes } from '../wallet';

type Me = { externalUserId: string; walletAddress: string; credentialId: string };
type Credential = { credentialId: string; walletAddress: string; createdAt: string };
type ChainRow = { chainId: number; name: string; deployed: boolean | null };

/**
 * Standalone view when the wallet page is opened directly (not via a dApp popup).
 *
 * Shows the account address ONCE — it is the same on every served chain (MC-16) — and one
 * row per chain with its deployment state there (MC-84). "Not yet deployed on this chain"
 * is normal, never an error: the account deploys lazily with its first transaction on each
 * chain (MC-29, MC-30). With one chain served this collapses to a single row (MC-89).
 */
export function Settings({ runtimes, config }: { runtimes: WalletRuntimes; config: WalletConfig }) {
  const [me, setMe] = useState<Me | null>(null);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [chainRows, setChainRows] = useState<ChainRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Any chain's runtime carries the shared, chain-agnostic session (MC-76); the first
  // configured chain is where a direct sign-in deploys the account.
  const runtime = runtimes.runtimeFor(runtimes.servedChainIds[0]);
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
      if (credsRes.ok) setCredentials(((await credsRes.json()) as { credentials: Credential[] }).credentials);
      if (meRes.ok) {
        const loadedMe = (await meRes.json()) as Me;
        setMe(loadedMe);
        // Per-chain deployment state, read from each chain itself.
        const rows = await Promise.all(
          runtimes.servedChainIds.map(async (chainId) => {
            const chainRuntime = runtimes.runtimeFor(chainId);
            const deployed = await chainRuntime
              .isAccountDeployed(loadedMe.walletAddress as `0x${string}`)
              .catch(() => null);
            return { chainId, name: chainRuntime.chainName, deployed };
          }),
        );
        setChainRows(rows);
      }
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
      setChainRows([]);
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
              <span className="v" data-testid="settings-address">{me.walletAddress}</span>
            </div>
            {chainRows.map((row) => (
              <div className="kv" key={row.chainId} data-testid={`settings-chain-${row.chainId}`}>
                <span className="k">
                  {row.name} ({row.chainId})
                </span>
                <span className="v">
                  {row.deployed === null ? 'status unavailable' : row.deployed ? 'deployed' : 'deploys with your first transaction'}
                </span>
              </div>
            ))}
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
