import {
  GianoPaymasterClient,
  assessHealth,
  type PaymasterOverview,
  type PaymasterRoleName,
  type HealthReport,
} from '@appliedblockchain/giano-paymaster-sdk';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Address } from 'viem';
import type { Deployment } from '../config';
import { createReadClient, type ConnectedWallet } from '../lib/chain';
import { describeError } from '../lib/format';

/**
 * Owns the SDK client and the overview it renders from.
 *
 * One `getOverview` call per refresh rather than a request per panel: every panel reads from the
 * same snapshot, so the header cannot show a solvency figure computed from a roster the tenants
 * table has not caught up with yet. Health is derived from that same snapshot locally — it is a
 * pure function of it, so recomputing costs nothing and cannot disagree with what is on screen.
 */
export type PaymasterState = {
  client: GianoPaymasterClient | undefined;
  overview: PaymasterOverview | undefined;
  health: HealthReport | undefined;
  /** Roles the connected wallet holds. Empty when read-only — which gates every write control. */
  myRoles: readonly PaymasterRoleName[];
  /**
   * False on a proxy predating the on-chain tenant roster, where the list was reconstructed from
   * registration logs instead. Surfaced rather than hidden: the log path cannot see a tenant whose
   * registration is outside the node's retained history, so the roster may be incomplete.
   */
  rosterOnChain: boolean;
  loading: boolean;
  /** Set when the last refresh failed. The previous overview stays on screen underneath it. */
  error: string | undefined;
  lastUpdated: Date | undefined;
  refresh: () => Promise<void>;
};

export function usePaymaster(deployment: Deployment, wallet: ConnectedWallet | undefined): PaymasterState {
  const publicClient = useMemo(() => createReadClient(deployment), [deployment]);

  const [client, setClient] = useState<GianoPaymasterClient>();
  const [overview, setOverview] = useState<PaymasterOverview>();
  const [myRoles, setMyRoles] = useState<readonly PaymasterRoleName[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [lastUpdated, setLastUpdated] = useState<Date>();
  const [rosterOnChain, setRosterOnChain] = useState(true);

  // Resolving the address may need a round-trip (the registry lookup), so the client is built once
  // and then rebound whenever the wallet changes — rebinding is cheap and needs no network.
  useEffect(() => {
    let cancelled = false;

    const build = async () => {
      try {
        const resolved = deployment.paymasterAddress
          ? new GianoPaymasterClient({ address: deployment.paymasterAddress, publicClient, walletClient: wallet?.walletClient })
          : await GianoPaymasterClient.fromRegistry({ publicClient, walletClient: wallet?.walletClient });
        if (!cancelled) setClient(resolved);
      } catch (cause) {
        if (!cancelled) {
          setError(describeError(cause));
          setLoading(false);
        }
      }
    };

    void build();
    return () => {
      cancelled = true;
    };
  }, [deployment.paymasterAddress, publicClient, wallet?.walletClient]);

  // A refresh in flight when another is requested would race; the ref lets a later one win.
  const generation = useRef(0);
  const verified = useRef(false);

  // A new client is a new address or a new chain, so the deployment check has to run again — and
  // the previous chain's snapshot has to go with it. Leaving it on screen while the new one loads
  // would show one deployment's balances under another's name, which is the exact confusion the
  // whole per-environment labelling exists to prevent.
  useEffect(() => {
    verified.current = false;
    setOverview(undefined);
    setMyRoles([]);
    setError(undefined);
    setLastUpdated(undefined);
    setLoading(true);
  }, [client]);

  const refresh = useCallback(async () => {
    if (!client) return;
    const current = ++generation.current;
    setLoading(true);

    try {
      // Checked once per client, not per refresh: an address with no code reads back as an empty
      // paymaster rather than an error, which looks exactly like a fresh deployment. A ref rather
      // than state because `refresh` must not change identity when it flips — the polling effect
      // depends on it.
      if (!verified.current) {
        await client.assertDeployed();
        setRosterOnChain(await client.hasOnChainRoster());
        verified.current = true;
      }

      const next = await client.getOverview({ withSlugs: true });
      if (generation.current !== current) return;

      setOverview(next);
      setError(undefined);
      setLastUpdated(new Date());

      // Role membership is read from the snapshot rather than with nine more calls: getOverview
      // already returned every role's holders.
      if (wallet) {
        const held = next.roles
          .filter((entry) => entry.name !== 'DEFAULT_ADMIN_ROLE')
          .filter((entry) => entry.holders.some((holder) => holder.toLowerCase() === wallet.address.toLowerCase()))
          .map((entry) => entry.name as PaymasterRoleName);
        setMyRoles(held);
      } else {
        setMyRoles([]);
      }
    } catch (cause) {
      if (generation.current === current) setError(describeError(cause));
    } finally {
      if (generation.current === current) setLoading(false);
    }
  }, [client, wallet]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Polling, because the chain has no push channel a browser can subscribe to over plain HTTP.
  useEffect(() => {
    if (!client || deployment.refreshSeconds <= 0) return;
    const timer = setInterval(() => void refresh(), deployment.refreshSeconds * 1000);
    return () => clearInterval(timer);
  }, [client, deployment.refreshSeconds, refresh]);

  const health = useMemo(() => (overview ? assessHealth(overview) : undefined), [overview]);

  return { client, overview, health, myRoles, rosterOnChain, loading, error, lastUpdated, refresh };
}

/** True when the connected wallet may perform an action gated by `role`. */
export function canAct(myRoles: readonly PaymasterRoleName[], role: PaymasterRoleName): boolean {
  return myRoles.includes(role);
}

export type { Address };
