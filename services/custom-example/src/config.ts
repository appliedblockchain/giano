import { z } from 'zod';

/**
 * Runtime configuration (demo-deployment spec).
 *
 * The container renders `window.__GIANO_CONFIG__` into /config.js at START from GIANO_* environment
 * variables (docker/entrypoint.sh) — never at build time — so one image serves every deployment and
 * both tenant shapes (R16). It is read synchronously because index.html loads /config.js ahead of the
 * bundle. Under `pnpm dev` the placeholder in public/config.js is null and every value falls back to
 * `import.meta.env.GIANO_*` (vite.config.ts exposes the GIANO_ prefix), read from .env.development and
 * .env.local — the same names as the container, so a developer's env file and a deployment's environment
 * are the same document.
 *
 * Validation happens here, in the browser, because the nginx image has no runtime to validate JSON in:
 * the entrypoint checks presence and shape at the edges, this schema checks everything, and App.tsx
 * renders a configuration-error screen instead of constructing any provider when it fails.
 */

const address = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 20-byte address')
  .transform((value) => value as `0x${string}`);

const rpcUrl = z.string().refine((value) => /^https?:\/\/[^\s]+$/.test(value) || /^\/rpc\/\d+$/.test(value), {
  message: 'must be an absolute http(s) URL or a same-origin /rpc/<chainId> path',
});

export const chainSchema = z.object({
  chainId: z.number().int().positive('must be a positive integer'),
  name: z.string().min(1),
  rpcUrl,
  explorerUrl: z.string().url().optional(),
  /** The default ERC-20 for this chain's token card — Giano's test token at its CREATE2 address. */
  defaultToken: address.optional(),
});

export const runtimeConfigSchema = z.object({
  /** The TENANT's wallet origin. Each dApp is pinned to exactly one. */
  walletUrl: z.string().url('required — the tenant wallet origin, e.g. https://wallet.example.dev'),
  /** A wallet origin that does NOT allow-list this dApp, for the disallowed-origin control. Optional. */
  otherWalletUrl: z.string().url().optional(),
  /** Free-text tag beside the title, to tell two instances of this image apart. */
  appLabel: z.string().optional(),
  chains: z.array(chainSchema).min(1, 'at least one chain is required'),
});

export type ChainConfig = z.infer<typeof chainSchema>;
export type RuntimeConfig = z.infer<typeof runtimeConfigSchema>;

export type ConfigIssue = { path: string; message: string };
export type ConfigResult = { ok: true; config: RuntimeConfig; source: 'container' | 'dev-env' } | { ok: false; issues: ConfigIssue[]; source: 'container' | 'dev-env' | 'none' };

declare global {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions -- global augmentation must be an interface
  interface Window {
    __GIANO_CONFIG__?: unknown;
  }
}

/** envsubst renders an unset variable as an empty string, which means "unset". */
const str = (value: unknown): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
};

/** Development fallbacks: the same GIANO_* names, from .env.development/.env.local, inlined by Vite for `pnpm dev` only. */
function fromDevEnv(): unknown {
  const env = import.meta.env as Record<string, string | undefined>;
  const walletUrl = str(env.GIANO_WALLET_URL);
  const chainsRaw = str(env.GIANO_CHAINS);
  if (!walletUrl && !chainsRaw) return undefined;
  let chains: unknown = undefined;
  if (chainsRaw) {
    try {
      chains = JSON.parse(chainsRaw);
    } catch {
      chains = chainsRaw; // let the schema report it
    }
  }
  return {
    walletUrl,
    otherWalletUrl: str(env.GIANO_OTHER_WALLET_URL),
    appLabel: str(env.GIANO_APP_LABEL),
    chains,
  };
}

function normalise(raw: unknown): unknown {
  if (!raw || typeof raw !== 'object') return raw;
  const record = raw as Record<string, unknown>;
  return {
    ...record,
    walletUrl: str(record.walletUrl),
    otherWalletUrl: str(record.otherWalletUrl),
    appLabel: str(record.appLabel),
    chains: Array.isArray(record.chains)
      ? record.chains.map((chain) =>
          chain && typeof chain === 'object'
            ? {
                ...(chain as Record<string, unknown>),
                explorerUrl: str((chain as Record<string, unknown>).explorerUrl),
                defaultToken: str((chain as Record<string, unknown>).defaultToken),
              }
            : chain,
        )
      : record.chains,
  };
}

export function loadRuntimeConfig(): ConfigResult {
  const injected = typeof window !== 'undefined' ? window.__GIANO_CONFIG__ : undefined;
  const raw = injected ?? fromDevEnv();
  if (raw === undefined || raw === null) {
    return {
      ok: false,
      source: 'none',
      issues: [
        { path: 'walletUrl', message: 'required — no runtime configuration was injected and no GIANO_WALLET_URL is set for development (.env.development)' },
        { path: 'chains', message: 'required — set GIANO_CHAINS to a JSON array of { chainId, name, rpcUrl }' },
      ],
    };
  }
  const source: 'container' | 'dev-env' = injected ? 'container' : 'dev-env';
  const parsed = runtimeConfigSchema.safeParse(normalise(raw));
  if (!parsed.success) {
    return {
      ok: false,
      source,
      issues: parsed.error.issues.map((issue) => ({ path: issue.path.join('.') || '(root)', message: issue.message })),
    };
  }
  const ids = parsed.data.chains.map((chain) => chain.chainId);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length) {
    return { ok: false, source, issues: duplicates.map((id) => ({ path: 'chains', message: `chain ${id} is listed more than once` })) };
  }
  return { ok: true, source, config: parsed.data };
}

/** The connector version this build was made against — inlined by vite.config.ts from the installed package. */
declare const __GIANO_CONNECTOR_VERSION__: string;
export const CONNECTOR_VERSION: string = typeof __GIANO_CONNECTOR_VERSION__ === 'string' ? __GIANO_CONNECTOR_VERSION__ : 'unknown';
