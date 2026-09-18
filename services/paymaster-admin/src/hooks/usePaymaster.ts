import {
  GianoPaymasterClient,
  assessHealth,
  type PaymasterOverview,
  type PaymasterRoleName,
  type HealthReport,
} from '@appliedblockchain/giano-paymaster-sdk';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Address, Hex } from 'viem';
import type { Deployment } from '../config';
import { createReadClient, type ConnectedWallet } from '../lib/chain';
import { describeError } from '../lib/format';
import { loadSlugs, rememberSlugs } from '../lib/slug-store';

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
   * registration logs instead. Surfaced rather than hidden: that path enumerates from one window of
   * logs, so the roster may be incomplete.
   */
  rosterOnChain: boolean;
  /**
   * True while some tenant on screen has no label yet.
   *
   * Slugs come from a window of registration logs, so a tenant registered before this browser first
   * opened the console shows its `bytes16` id until {@link PaymasterState.findOlderSlugs} reaches
   * back far enough. The id is the tenant's real on-chain identity, so nothing is unusable — it is a
   * missing label, not a missing row.
   */
  slugsIncomplete: boolean;
  /** Reads one more window of registrations, older than anything read so far. */
  findOlderSlugs: () => Promise<void>;
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

  // Slugs accumulate across refreshes and across reloads rather than being re-read each time — see
  // `lib/slug-store`. A ref rather than state because `refresh` reads and writes it on every poll
  // and must not change identity when it does; what renders is the slug already on each TenantView.
  const slugs = useRef<ReadonlyMap<Hex, string>>(new Map());
  /** The oldest window of registrations read so far, so "look further back" knows where to resume. */
  const slugFloor = useRef<{ fromBlock: bigint; toBlock: bigint } | undefined>(undefined);

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
    // Another deployment's labels must not appear under this one's tenant ids, so the remembered
    // map is reloaded for the deployment now on screen rather than carried across.
    slugs.current = client ? loadSlugs(deployment.chainId, client.address) : new Map();
    slugFloor.current = undefined;
    setOverview(undefined);
    setMyRoles([]);
    setError(undefined);
    setLastUpdated(undefined);
    setLoading(true);
  }, [client, deployment.chainId]);

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

      // The roster and the labels are read separately, in parallel, rather than through
      // `getOverview({ withSlugs: true })`. Same number of requests, and it is the only way to learn
      // *which blocks* the labels came from — which this panel has to say on screen, and which
      // `findOlderSlugs` needs in order to step past.
      const [next, registered] = await Promise.all([client.getOverview({ withSlugs: false }), client.getTenantSlugs()]);
      if (generation.current !== current) return;

      // The poll interval is far shorter than a window is wide, so in steady state every
      // registration is observed as it lands and the remembered map converges on complete without
      // anyone paging back for it.
      slugs.current = rememberSlugs(deployment.chainId, client.address, slugs.current, registered.slugs);
      slugFloor.current ??= registered.older;

      next.tenants = next.tenants.map((tenant) => ({ ...tenant, slug: slugs.current.get(tenant.id) }));

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
  }, [client, wallet, deployment.chainId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Polling, because the chain has no push channel a browser can subscribe to over plain HTTP.
  useEffect(() => {
    if (!client || deployment.refreshSeconds <= 0) return;
    const timer = setInterval(() => void refresh(), deployment.refreshSeconds * 1000);
    return () => clearInterval(timer);
  }, [client, deployment.refreshSeconds, refresh]);

  /**
   * Steps one window further into the past looking for registrations.
   *
   * Explicit rather than automatic: walking back to a deployment's first block is what this whole
   * design exists to avoid, and an operator asking for one more window at a time is the bounded
   * version of that. What it finds is remembered, so the walk is paid once per browser.
   */
  const findOlderSlugs = useCallback(async () => {
    if (!client || !slugFloor.current) return;
    setLoading(true);
    try {
      const page = await client.getTenantSlugs(slugFloor.current);
      slugFloor.current = page.older;
      slugs.current = rememberSlugs(deployment.chainId, client.address, slugs.current, page.slugs);

      setOverview((previous) =>
        previous ? { ...previous, tenants: previous.tenants.map((tenant) => ({ ...tenant, slug: slugs.current.get(tenant.id) })) } : previous,
      );
      setError(undefined);
    } catch (cause) {
      setError(describeError(cause));
    } finally {
      setLoading(false);
    }
  }, [client, deployment.chainId]);

  const health = useMemo(() => (overview ? assessHealth(overview) : undefined), [overview]);
  // Only actionable while there are older blocks left to read: at genesis an unlabelled tenant is
  // one whose registration is not on this chain at all, and offering to look further back would be
  // a button that cannot help.
  const slugsIncomplete = useMemo(
    () => (overview?.tenants ?? []).some((tenant) => !tenant.slug) && slugFloor.current !== undefined,
    [overview],
  );

  return { client, overview, health, myRoles, rosterOnChain, slugsIncomplete, findOlderSlugs, loading, error, lastUpdated, refresh };
}

/** True when the connected wallet may perform an action gated by `role`. */
export function canAct(myRoles: readonly PaymasterRoleName[], role: PaymasterRoleName): boolean {
  return myRoles.includes(role);
}

export type { Address };
