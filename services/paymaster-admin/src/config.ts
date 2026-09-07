/**
 * Runtime configuration, fetched from `/config.json` before the first render.
 *
 * Deliberately not build-time `VITE_` variables: one published image has to serve every
 * deployment, and a console baked to a single chain and paymaster address would need a rebuild per
 * environment — which is exactly when someone points the production console at a devnet by
 * accident. The container renders the same file from environment variables at boot.
 *
 * The file declares a *list* of deployments the console may administer. That list is the whole of
 * what it can reach: an operator picks between environments someone deliberately configured, and
 * cannot point the console at an arbitrary chain by typing into it. Which is the useful half of
 * the safety property — switching between known environments is routine; reaching an unknown one
 * by accident is what must stay impossible.
 */

/** One paymaster deployment the console can administer. */
export type Deployment = {
  /** How an operator tells this environment apart. Shown in the header. */
  label: string;
  chainId: number;
  rpcUrl: string;
  /**
   * The paymaster proxy.
   *
   * Optional in the type because the SDK can resolve it from the contracts registry — but no chain
   * in that registry currently declares a `sponsorshipPaymaster`, so in practice this must be set.
   * Leaving it out fails loudly rather than silently reading the wrong contract.
   */
  paymasterAddress?: `0x${string}`;
  /** Seconds between automatic refreshes. 0 disables polling. */
  refreshSeconds: number;
};

export type AdminConfig = {
  deployments: readonly Deployment[];
};

/**
 * The file as it actually arrives, before validation.
 *
 * Loosely typed because the container renders it from environment variables: an unset optional
 * variable substitutes to `""`, not to an absent key, and typing it as the validated shape would
 * let those empty strings through as real addresses.
 */
type RawDeployment = {
  label?: string;
  chainId?: number | string;
  rpcUrl?: string;
  paymasterAddress?: string;
  refreshSeconds?: number | string;
};

type RawAdminConfig = RawDeployment & {
  deployments?: RawDeployment[];
  /** Accepted at the top level for the single-deployment shape. */
  environmentLabel?: string;
};

let config: AdminConfig | undefined;

const DEFAULT_REFRESH_SECONDS = 15;

function toDeployment(raw: RawDeployment, fallbackLabel: string, index: number): Deployment {
  const chainId = Number(raw.chainId);
  if (!chainId || Number.isNaN(chainId)) throw new Error(`deployment ${index + 1} (${raw.label ?? fallbackLabel}) has no chainId`);
  if (!raw.rpcUrl) throw new Error(`deployment ${index + 1} (${raw.label ?? fallbackLabel}) has no rpcUrl`);

  return {
    label: raw.label || fallbackLabel || `chain ${chainId}`,
    chainId,
    rpcUrl: raw.rpcUrl,
    paymasterAddress: raw.paymasterAddress ? (raw.paymasterAddress as `0x${string}`) : undefined,
    refreshSeconds: raw.refreshSeconds === undefined || raw.refreshSeconds === '' ? DEFAULT_REFRESH_SECONDS : Number(raw.refreshSeconds),
  };
}

export async function loadAdminConfig(): Promise<AdminConfig> {
  if (config) return config;

  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`failed to load /config.json: ${response.status}`);
  const raw = (await response.json()) as RawAdminConfig;

  // Two accepted shapes. The single-deployment one is kept because it is what a container
  // rendering one set of environment variables produces, and because most deployments really do
  // administer one chain — making them declare a one-element array would be ceremony.
  const rawDeployments = raw.deployments && raw.deployments.length > 0 ? raw.deployments : [{ ...raw, label: raw.label ?? raw.environmentLabel }];

  const deployments = rawDeployments.map((entry, index) => toDeployment(entry, entry.label ?? '', index));

  const seen = new Set<string>();
  for (const deployment of deployments) {
    const key = deploymentKey(deployment);
    if (seen.has(key)) throw new Error(`two deployments share chain ${deployment.chainId} and the same paymaster address; give them distinct addresses`);
    seen.add(key);
  }

  config = { deployments };
  return config;
}

/** The loaded config. Throws if called before {@link loadAdminConfig} has resolved. */
export function getAdminConfig(): AdminConfig {
  if (!config) throw new Error('admin config accessed before it was loaded');
  return config;
}

/**
 * A stable identity for a deployment, used to remember the operator's choice.
 *
 * Keyed on chain and address rather than on the label: a label is prose and gets reworded, and a
 * remembered selection that silently moved to a different environment because someone fixed a typo
 * would be worse than not remembering it at all.
 */
export function deploymentKey(deployment: Deployment): string {
  return `${deployment.chainId}:${deployment.paymasterAddress?.toLowerCase() ?? 'registry'}`;
}

const STORAGE_KEY = 'giano:paymaster-admin:deployment';

/** The deployment to open with: the one last chosen, when it is still declared, else the first. */
export function initialDeployment(deployments: readonly Deployment[]): Deployment {
  try {
    const remembered = localStorage.getItem(STORAGE_KEY);
    const match = deployments.find((deployment) => deploymentKey(deployment) === remembered);
    if (match) return match;
  } catch {
    // Storage can be unavailable (private mode, blocked cookies). Not remembering is fine.
  }
  return deployments[0];
}

export function rememberDeployment(deployment: Deployment): void {
  try {
    localStorage.setItem(STORAGE_KEY, deploymentKey(deployment));
  } catch {
    // As above — a console that cannot remember the choice still works.
  }
}
