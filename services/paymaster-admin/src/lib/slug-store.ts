import type { Hex } from 'viem';

/**
 * Remembered tenant slugs.
 *
 * A slug is emitted by `TenantRegistered` and never stored on chain, and the console reads logs one
 * window at a time (INFRASTRUCTURE §14.6) — so a tenant registered before the current window has no
 * label in this refresh's answer. Forgetting it between refreshes would make labels flicker in and
 * out as the window slides past each registration.
 *
 * Registrations are append-only and a slug is never revised, so remembering is safe in the way a
 * balance cache would not be: the worst a stale entry can be is the name of a tenant that has since
 * been removed from the roster, and a removed tenant is not rendered at all.
 *
 * Kept per chain and paymaster, because the same tenant id means a different deployment's tenant on
 * a different contract, and the console switches between deployments.
 */

const KEY_PREFIX = 'giano.paymaster-admin.slugs';

/** A browser with storage disabled or full must not break the console; labels are not load-bearing. */
function safely<T>(operation: () => T, fallback: T): T {
  try {
    return operation();
  } catch {
    return fallback;
  }
}

function key(chainId: number, paymaster: string): string {
  return `${KEY_PREFIX}.${chainId}.${paymaster.toLowerCase()}`;
}

export function loadSlugs(chainId: number, paymaster: string): Map<Hex, string> {
  return safely(() => {
    const raw = window.localStorage.getItem(key(chainId, paymaster));
    if (!raw) return new Map<Hex, string>();
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return new Map<Hex, string>();
    return new Map(Object.entries(parsed as Record<string, string>).filter(([, slug]) => typeof slug === 'string') as Array<[Hex, string]>);
  }, new Map<Hex, string>());
}

/** Merges what a read found into what was already known, and returns the union. */
export function rememberSlugs(chainId: number, paymaster: string, known: ReadonlyMap<Hex, string>, found: ReadonlyMap<Hex, string>): Map<Hex, string> {
  const merged = new Map(known);
  for (const [id, slug] of found) merged.set(id, slug);

  if (merged.size !== known.size) {
    safely(() => window.localStorage.setItem(key(chainId, paymaster), JSON.stringify(Object.fromEntries(merged))), undefined);
  }
  return merged;
}
