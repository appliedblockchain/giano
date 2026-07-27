import { useCallback, useEffect, useState } from 'react';
import { provider } from '../giano';
import { notifyError } from '../lib/notify';

type Address = `0x${string}`;

/**
 * Wallet connection state driven entirely by the thin EIP-1193 provider.
 * Restores a cached session on mount and tracks the popup's accountsChanged/disconnect events.
 */
export function useWallet() {
  const [account, setAccount] = useState<Address | null>(null);
  const [connecting, setConnecting] = useState(false);

  useEffect(() => {
    // eth_accounts answers from the cached session without opening a popup.
    provider
      .request<string[]>({ method: 'eth_accounts' })
      .then((accounts) => setAccount((accounts?.[0] as Address) ?? null))
      .catch(() => setAccount(null));

    const onAccountsChanged = (payload: unknown) => {
      const accounts = payload as string[];
      setAccount((accounts?.[0] as Address) ?? null);
    };
    const onDisconnect = () => setAccount(null);

    provider.on('accountsChanged', onAccountsChanged);
    provider.on('disconnect', onDisconnect);
    return () => {
      provider.removeListener('accountsChanged', onAccountsChanged);
      provider.removeListener('disconnect', onDisconnect);
    };
  }, []);

  const connect = useCallback(async () => {
    setConnecting(true);
    try {
      const accounts = await provider.request<string[]>({ method: 'eth_requestAccounts' });
      setAccount((accounts?.[0] as Address) ?? null);
    } catch (error) {
      notifyError('Connection failed', error);
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    provider.disconnect();
    setAccount(null);
  }, []);

  return { account, connecting, connect, disconnect };
}
