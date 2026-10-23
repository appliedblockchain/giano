import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { isUserRejection, type ConnectedWallet } from './chain';
import { operatorApi, operatorAuth, OperatorUnauthorized, type ApiResult, type OperatorApi } from './operator-api';

/**
 * The operator session, held in memory and nowhere else (specs/OPERATOR-ADMIN-SPECS.md §4.6).
 *
 * Not localStorage, not sessionStorage, not a cookie: a token any script on this origin could read
 * back is a token a single injected script walks off with, and one that survives a reload outlives
 * the wallet it was signed by. So a reload signs in again — one wallet prompt — and the session
 * also ends when the wallet changes account or chain (the console reloads on both), when the
 * deployment changes (the provider is keyed on it and remounts), at its expiry, and on any 401.
 */

export type OperatorSession = { token: string; operator: { id: string; address: string }; expiresAt: Date };

/** Why sign-in did not produce a session. `rejected` is the operator declining in the wallet: not an error. */
export type SignInFailure = 'rejected' | 'not-operator' | 'disabled' | 'failed';

type OperatorContextValue = {
  session: OperatorSession | undefined;
  /** Set when a session ended on its own (expiry or 401), so the sign-in view can say so. */
  endedNotice: string | undefined;
  signIn: (wallet: ConnectedWallet, chainId: number) => Promise<{ ok: true } | { ok: false; reason: SignInFailure; message?: string }>;
  signOut: () => Promise<void>;
  /**
   * Runs an operator call with the session's token. Resolves to undefined when the session ended
   * under it, having already dropped the session — callers only ever handle a result.
   */
  run: <T>(call: (api: OperatorApi) => Promise<ApiResult<T>>) => Promise<ApiResult<T> | undefined>;
};

const OperatorContext = createContext<OperatorContextValue | undefined>(undefined);

export function OperatorSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<OperatorSession>();
  const [endedNotice, setEndedNotice] = useState<string>();

  const end = useCallback((notice?: string) => {
    setSession(undefined);
    setEndedNotice(notice);
  }, []);

  // The API refuses an expired session anyway; ending it here means the console says so at the
  // moment it happens rather than on the operator's next click.
  useEffect(() => {
    if (!session) return;
    const timer = setTimeout(() => end('Your operator session expired. Sign in again to continue.'), Math.max(0, session.expiresAt.getTime() - Date.now()));
    return () => clearTimeout(timer);
  }, [session, end]);

  const signIn = useCallback<OperatorContextValue['signIn']>(async (wallet, chainId) => {
    setEndedNotice(undefined);
    try {
      const challenge = await operatorAuth.challenge(wallet.address, chainId);
      if (!challenge.ok) {
        if (challenge.error.status === 404) return { ok: false, reason: 'disabled' };
        return { ok: false, reason: 'failed', message: challenge.error.message };
      }
      // Signed exactly as the server wrote it: the console never builds or edits a sign-in message,
      // so it has no say over which domain the operator is asked to sign for.
      const signature = await wallet.walletClient.signMessage({ account: wallet.address, message: challenge.value.message });
      const verified = await operatorAuth.verify(challenge.value.message, signature);
      if (!verified.ok) {
        if (verified.error.status === 401) return { ok: false, reason: 'not-operator' };
        return { ok: false, reason: 'failed', message: verified.error.message };
      }
      setSession({ token: verified.value.token, operator: verified.value.operator, expiresAt: new Date(verified.value.expiresAt) });
      return { ok: true };
    } catch (cause) {
      if (isUserRejection(cause)) return { ok: false, reason: 'rejected' };
      return { ok: false, reason: 'failed', message: cause instanceof Error ? cause.message : String(cause) };
    }
  }, []);

  const signOut = useCallback(async () => {
    const token = session?.token;
    end();
    // Forgotten first, revoked second: a failed logout must not leave the console signed in.
    if (token) await operatorAuth.logout(token).catch(() => undefined);
  }, [session, end]);

  const run = useCallback<OperatorContextValue['run']>(
    async (call) => {
      if (!session) return undefined;
      try {
        return await call(operatorApi(session.token));
      } catch (cause) {
        if (cause instanceof OperatorUnauthorized) {
          end('Your operator session ended. Sign in again to continue.');
          return undefined;
        }
        throw cause;
      }
    },
    [session, end],
  );

  const value = useMemo(() => ({ session, endedNotice, signIn, signOut, run }), [session, endedNotice, signIn, signOut, run]);
  return createElement(OperatorContext.Provider, { value }, children);
}

export function useOperator(): OperatorContextValue {
  const value = useContext(OperatorContext);
  if (!value) throw new Error('useOperator outside OperatorSessionProvider');
  return value;
}
