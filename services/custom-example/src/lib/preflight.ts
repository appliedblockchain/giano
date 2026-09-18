import type { ChainConfig, RuntimeConfig } from '../config';
import type { ChainRegistry } from './chains';

/**
 * Setup preflight (design.md D14). Six checks that answer in under a second what a 15 s handshake
 * timeout or a 120 s receipt timeout would otherwise answer — each with the operator action that fixes
 * it. Nothing here blocks the page; a failed row disables the write controls it invalidates or attaches
 * a warning to them.
 */
export type CheckState = 'pass' | 'warn' | 'fail' | 'running';

export type PreflightCheck = {
  id: string;
  title: string;
  state: CheckState;
  /** What was observed, verbatim (URL, status, values). */
  detail: string;
  /** What to do about it, when it is not a pass. */
  action?: string;
  chainId?: number;
};

export type PreflightResult = {
  at: string;
  durationMs: number;
  checks: PreflightCheck[];
  /** Chains whose RPC answered a different chain id: their write controls are disabled. */
  wrongNetworkChainIds: number[];
  /** The wallet origin fetch failed: receipts will not be readable from this origin. */
  receiptsAtRisk: boolean;
  walletApiVersion?: string;
};

export type VersionResponse = { version: string; chainId: number | null; chains: Array<{ chainId: number; name: string; status: 'ready' | 'unavailable' }> };

async function checkWalletOrigin(walletUrl: string, walletApiPath: string, connectorVersion: string): Promise<{ checks: PreflightCheck[]; apiVersion?: string; corsFailed: boolean }> {
  const url = `${new URL(walletUrl).origin}${walletApiPath}/v1/version`;
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) {
      return {
        corsFailed: false,
        checks: [
          {
            id: 'wallet',
            title: 'Wallet origin reachable',
            state: 'fail',
            detail: `GET ${url} → ${response.status}`,
            action: 'The wallet origin answers but its /api proxy does not reach wallet-api. Check GIANO_WALLET_API_UPSTREAM on wallet-web, or walletApiPath in the provider options.',
          },
        ],
      };
    }
    const body = (await response.json()) as VersionResponse;
    const served = body.chains.map((chain) => `${chain.chainId} ${chain.status}`).join(', ');
    const checks: PreflightCheck[] = [
      { id: 'wallet', title: 'Wallet origin reachable', state: 'pass', detail: `GET ${url} → 200 · wallet-api ${body.version} · CORS allows ${window.location.origin} · serves ${served}` },
    ];
    const skew = compareVersions(connectorVersion, body.version);
    checks.push(
      skew > 0
        ? {
            id: 'version',
            title: 'Version skew',
            state: 'warn',
            detail: `connector ${connectorVersion} · wallet-api ${body.version}`,
            action: 'The SDK is ahead of the wallet-api. Upgrade order is wallet-api → wallet-web → SDK (COMPATIBILITY.md); roll the SDK back or upgrade the api.',
          }
        : { id: 'version', title: 'Version skew', state: 'pass', detail: `connector ${connectorVersion} · wallet-api ${body.version}` },
    );
    return { checks, apiVersion: body.version, corsFailed: false };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      corsFailed: true,
      checks: [
        {
          id: 'wallet',
          title: 'Wallet origin reachable',
          state: 'fail',
          detail: `GET ${url} failed: ${message}`,
          action: `Either the wallet origin is down, or ${window.location.origin} is not in the tenant's corsOrigins (the fetch is blocked by CORS), or this page's CSP connect-src omits the wallet origin. Until fixed, connecting may work but receipts will not be readable from this origin.`,
        },
        { id: 'version', title: 'Version skew', state: 'warn', detail: `connector ${connectorVersion} · wallet-api unknown`, action: 'Cannot compare versions until the wallet origin answers.' },
      ],
    };
  }
}

async function checkCoop(): Promise<PreflightCheck> {
  try {
    const response = await fetch(window.location.href, { cache: 'no-store', signal: AbortSignal.timeout(5000) });
    const coop = response.headers.get('cross-origin-opener-policy');
    if (coop && /^same-origin$/i.test(coop.trim())) {
      return {
        id: 'coop',
        title: 'Own COOP header',
        state: 'fail',
        detail: `Cross-Origin-Opener-Policy: ${coop}`,
        action: 'This severs window.opener and the popup handshake times out. Serve this page with same-origin-allow-popups or no COOP header.',
      };
    }
    return { id: 'coop', title: 'Own COOP header', state: 'pass', detail: coop ? `Cross-Origin-Opener-Policy: ${coop}` : 'no Cross-Origin-Opener-Policy header' };
  } catch (error) {
    return { id: 'coop', title: 'Own COOP header', state: 'warn', detail: `could not re-fetch this page: ${error instanceof Error ? error.message : String(error)}` };
  }
}

async function checkChain(registry: ChainRegistry, config: ChainConfig): Promise<PreflightCheck[]> {
  const entry = registry.require(config.chainId);
  const checks: PreflightCheck[] = [];
  try {
    const observed = await entry.publicClient.getChainId();
    if (observed !== config.chainId) {
      checks.push({
        id: `rpc-${config.chainId}`,
        chainId: config.chainId,
        title: `RPC chain id · ${config.name}`,
        state: 'fail',
        detail: `${config.rpcUrl} eth_chainId → ${observed} · configured ${config.chainId}`,
        action: `This RPC serves another network; reads on ${config.name} would be silently wrong. Write controls for ${config.name} are disabled until GIANO_CHAINS is fixed.`,
      });
    } else {
      checks.push({ id: `rpc-${config.chainId}`, chainId: config.chainId, title: `RPC chain id · ${config.name}`, state: 'pass', detail: `${config.rpcUrl} eth_chainId → ${observed} · matches configuration` });
    }
  } catch (error) {
    checks.push({
      id: `rpc-${config.chainId}`,
      chainId: config.chainId,
      title: `RPC chain id · ${config.name}`,
      state: 'fail',
      detail: `${config.rpcUrl} unreachable: ${error instanceof Error ? error.message : String(error)}`,
      action: 'Balances and token reads for this chain will fail. Check the RPC URL, its CORS headers (a keyed provider usually needs the /rpc/<chainId> proxy), and this page\'s CSP connect-src.',
    });
    return checks;
  }
  if (config.defaultToken) {
    try {
      const code = await entry.publicClient.getCode({ address: config.defaultToken });
      checks.push(
        code && code !== '0x'
          ? { id: `token-${config.chainId}`, chainId: config.chainId, title: `Default token · ${config.name}`, state: 'pass', detail: `eth_getCode(${config.defaultToken}) → ${code.length / 2 - 1} bytes` }
          : {
              id: `token-${config.chainId}`,
              chainId: config.chainId,
              title: `Default token · ${config.name}`,
              state: 'warn',
              detail: `eth_getCode(${config.defaultToken}) → 0x`,
              action: `No contract at the default token address on ${config.name}. The ERC-20 card opens empty for this chain; deploy Giano's test ERC-20 there (CREATE2) or fix defaultToken.`,
            },
      );
    } catch (error) {
      checks.push({ id: `token-${config.chainId}`, chainId: config.chainId, title: `Default token · ${config.name}`, state: 'warn', detail: `eth_getCode failed: ${error instanceof Error ? error.message : String(error)}` });
    }
  }
  return checks;
}

function checkStorage(): PreflightCheck {
  try {
    const key = 'giano-demo:probe';
    localStorage.setItem(key, '1');
    const ok = localStorage.getItem(key) === '1';
    localStorage.removeItem(key);
    if (!ok) throw new Error('read back a different value');
    return { id: 'storage', title: 'Browser storage', state: 'pass', detail: 'localStorage write/read ok · session resume and the ledger persist' };
  } catch (error) {
    return {
      id: 'storage',
      title: 'Browser storage',
      state: 'warn',
      detail: `localStorage unavailable: ${error instanceof Error ? error.message : String(error)}`,
      action: 'Session resume is off and the ledger will not survive a reload (private window or blocked site data). The provider can be given an in-memory storage in its options.',
    };
  }
}

/** Positive when a is ahead of b. Compares the numeric prefix only; pre-release tags are ignored. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => v.replace(/^v/, '').split(/[.-]/).slice(0, 3).map((part) => Number.parseInt(part, 10) || 0);
  const [a1, a2, a3] = parse(a);
  const [b1, b2, b3] = parse(b);
  return a1 - b1 || a2 - b2 || a3 - b3;
}

export async function runPreflight(config: RuntimeConfig, registry: ChainRegistry, connectorVersion: string): Promise<PreflightResult> {
  const started = Date.now();
  const walletApiPath = registry.optionsFor(config.chains[0].chainId).walletApiPath;
  const [wallet, coop, ...chains] = await Promise.all([checkWalletOrigin(config.walletUrl, walletApiPath, connectorVersion), checkCoop(), ...config.chains.map((chain) => checkChain(registry, chain))]);
  const chainChecks = chains.flat();
  const checks: PreflightCheck[] = [wallet.checks[0], coop, ...chainChecks, checkStorage(), wallet.checks[1]];
  return {
    at: new Date().toISOString(),
    durationMs: Date.now() - started,
    checks,
    wrongNetworkChainIds: chainChecks.filter((check) => check.id.startsWith('rpc-') && check.state === 'fail' && /configured/.test(check.detail)).map((check) => check.chainId!),
    receiptsAtRisk: wallet.corsFailed,
    walletApiVersion: wallet.apiVersion,
  };
}

export function summarise(result: PreflightResult): { state: CheckState; fails: PreflightCheck[]; warns: PreflightCheck[] } {
  const fails = result.checks.filter((check) => check.state === 'fail');
  const warns = result.checks.filter((check) => check.state === 'warn');
  return { state: fails.length ? 'fail' : warns.length ? 'warn' : 'pass', fails, warns };
}
