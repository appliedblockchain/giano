import { createHash } from 'node:crypto';
import * as http from 'node:http';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { buildApp } from '../src/app.js';
import { loadConfig, type AppConfig } from '../src/config.js';
import { createDb, type Db } from '../src/db/index.js';
import { runMigrations } from '../src/migrate.js';
import { seedTenants } from '../src/services/tenants.js';

/**
 * Two seeded tenants. Tenant A keeps the pre-tenancy test values (origin
 * localhost:4000, rpId localhost) so the webauthn fixtures and most assertions carry
 * over; tenant B exists to prove isolation and runs with closed registration.
 */
export const TENANT_A = {
  slug: 'alpha',
  walletOrigin: 'http://localhost:4000',
  rpId: 'localhost',
  rpName: 'Giano Test A',
  adminKey: 'test-admin-key-alpha',
  openRegistration: true,
};
export const TENANT_B = {
  slug: 'beta',
  walletOrigin: 'http://wallet-b.localhost:4100',
  rpId: 'wallet-b.localhost',
  rpName: 'Giano Test B',
  adminKey: 'test-admin-key-beta1',
  openRegistration: false,
};

export const TEST_ORIGIN = TENANT_A.walletOrigin;
export const TEST_RP_ID = TENANT_A.rpId;
export const ADMIN_KEY = TENANT_A.adminKey;

/**
 * Mutable owner-set state for the mock chain, standing in for what the account contract
 * would report. Wallet-management endpoints refuse to update the registry unless the chain
 * confirms the change (WM-15, WM-31) — tests move this state to play the chain's part.
 */
export type MockChainState = {
  /** lowercased addresses that have code (the account deploys lazily). */
  contracts: Set<string>;
  /** lowercased `${x}:${y}` 32-byte-hex pairs currently in the owner set. */
  ownerKeys: Set<string>;
  /** lowercased Ethereum-address owners. */
  ownerAddresses: Set<string>;
};

export function createMockChainState(): MockChainState {
  return { contracts: new Set(), ownerKeys: new Set(), ownerAddresses: new Set() };
}

export const ownerKeyOf = (x: string, y: string) => `${x.toLowerCase()}:${y.toLowerCase()}`;

const BOOL_TRUE = `0x${'0'.repeat(63)}1`;
const BOOL_FALSE = `0x${'0'.repeat(64)}`;
// keccak-derived 4-byte selectors for the MultiOwnable views the backend reads
const SEL_IS_OWNER_PUBLIC_KEY = '0x066a1eb7'; // isOwnerPublicKey(bytes32,bytes32)
const SEL_IS_OWNER_ADDRESS = '0xa2e1a8d8'; // isOwnerAddress(address)

/**
 * Tiny JSON-RPC stub standing in for the chain RPC. factory.getAddress → an address
 * DERIVED from the call data (which encodes the owner public key), so distinct
 * credentials get distinct wallet addresses — and the same credential registered on
 * two tenants gets the SAME address, mirroring the real tenant-agnostic derivation.
 * With a `MockChainState` it also answers the owner-set reads (isOwnerPublicKey,
 * isOwnerAddress, eth_getCode) the wallet-management endpoints verify against.
 */
export function startMockRpc(chainState?: MockChainState): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      const { id, method, params } = JSON.parse(body) as { id: number; method: string; params?: [{ data?: string; to?: string }, ...unknown[]] };
      let result: string = '0x0';
      if (method === 'eth_call') {
        const data = params?.[0]?.data ?? '0x';
        const selector = data.slice(0, 10).toLowerCase();
        if (chainState && selector === SEL_IS_OWNER_PUBLIC_KEY) {
          const x = `0x${data.slice(10, 74)}`;
          const y = `0x${data.slice(74, 138)}`;
          result = chainState.ownerKeys.has(ownerKeyOf(x, y)) ? BOOL_TRUE : BOOL_FALSE;
        } else if (chainState && selector === SEL_IS_OWNER_ADDRESS) {
          const owner = `0x${data.slice(34, 74)}`.toLowerCase();
          result = chainState.ownerAddresses.has(owner) ? BOOL_TRUE : BOOL_FALSE;
        } else {
          const digest = createHash('sha256').update(data).digest('hex');
          result = `0x${'0'.repeat(24)}${digest.slice(0, 40)}`; // abi-encoded address
        }
      } else if (method === 'eth_getCode') {
        const address = String((params as unknown as [string])?.[0] ?? '').toLowerCase();
        result = chainState?.contracts.has(address) ? '0x6080' : '0x';
      } else if (method === 'eth_chainId') {
        result = '0x7a69';
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

export type BundlerCall = { method: string; params: unknown[]; url: string };

/** Fetch stub for the bundler URL, recording calls (with the URL — per-chain routing is
 *  observable, MC-113) and answering with canned results. */
export function createMockBundlerFetch(results: Record<string, unknown> = {}) {
  const calls: BundlerCall[] = [];
  const fetchImpl: typeof fetch = async (url, init) => {
    const { id, method, params } = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
    calls.push({ method, params, url: String(url) });
    const result =
      method in results ? results[method] : method === 'eth_sendUserOperation' ? '0x' + 'ab'.repeat(32) : null;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), {
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetchImpl, calls };
}

export type TestContext = {
  container: StartedPostgreSqlContainer;
  db: Db;
  pool: { end: () => Promise<void> };
  rpc: { url: string; close: () => Promise<void> };
  config: AppConfig;
  app: Awaited<ReturnType<typeof buildApp>>;
  bundlerCalls: BundlerCall[];
  /** The mock chain's owner-set state — what wallet-management verification reads. */
  chainState: MockChainState;
};

const tenantSeedJson = JSON.stringify([
  {
    slug: TENANT_A.slug,
    walletOrigin: TENANT_A.walletOrigin,
    rpId: TENANT_A.rpId,
    rpName: TENANT_A.rpName,
    openRegistration: TENANT_A.openRegistration,
    adminKeys: [TENANT_A.adminKey],
    corsOrigins: ['http://dapp-a.localhost:4000'],
  },
  {
    slug: TENANT_B.slug,
    walletOrigin: TENANT_B.walletOrigin,
    rpId: TENANT_B.rpId,
    rpName: TENANT_B.rpName,
    openRegistration: TENANT_B.openRegistration,
    adminKeys: [TENANT_B.adminKey],
  },
]);

export async function startTestStack(envOverrides: Record<string, string> = {}): Promise<TestContext> {
  const container = await new PostgreSqlContainer('postgres:17-alpine').start();
  const databaseUrl = container.getConnectionUri();
  await runMigrations(databaseUrl);

  const chainState = createMockChainState();
  const rpc = await startMockRpc(chainState);
  const { fetchImpl, calls } = createMockBundlerFetch();

  const baseEnv: Record<string, string> = {
    NODE_ENV: 'test',
    GIANO_DEPLOYMENT_CLASS: 'development',
    LOG_LEVEL: 'error',
    DATABASE_URL: databaseUrl,
    TENANTS_SEED: tenantSeedJson,
    CHAIN_ID: '31337',
    RPC_URL: rpc.url,
    BUNDLER_URL: 'http://bundler.test',
    ENTRYPOINT_ADDRESS: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
    FACTORY_ADDRESS: '0x2222222222222222222222222222222222222222',
    CEREMONY_RATE_LIMIT_PER_MINUTE: '1000',
    USEROP_RATE_LIMIT_PER_MINUTE: '1000',
  };
  // GIANO_CHAINS and the scalar shorthand are mutually exclusive by design: a test that
  // supplies the list gets the scalars dropped rather than a config error.
  if (envOverrides.GIANO_CHAINS) {
    for (const key of ['CHAIN_ID', 'RPC_URL', 'BUNDLER_URL', 'ENTRYPOINT_ADDRESS', 'FACTORY_ADDRESS']) delete baseEnv[key];
  }
  const config = loadConfig({ ...baseEnv, ...envOverrides } as NodeJS.ProcessEnv);

  const { db, pool } = createDb(databaseUrl);
  // the production write path — tenant seeds run the same validation as a real boot
  await seedTenants(db, config.TENANTS_SEED);
  const app = await buildApp({ config, db, fetchImpl });
  return { container, db, pool, rpc, config, app, bundlerCalls: calls, chainState };
}

export async function stopTestStack(ctx: TestContext): Promise<void> {
  await ctx.app.close();
  await ctx.pool.end();
  await ctx.rpc.close();
  await ctx.container.stop();
}

// ── Sponsorship fixtures ───────────────────────────────────────────────────────

/**
 * A deterministic key for the sponsorship signer in tests. `loadConfig` refuses a local key when
 * `GIANO_DEPLOYMENT_CLASS=production`, so this can only ever be a test key.
 */
export const TEST_SPONSORSHIP_SIGNER_KEY = '0x0000000000000000000000000000000000000000000000000000000000005160';
export const TEST_PAYMASTER_ADDRESS = '0x15a2075f2407427C5dd0BDe9d1966c48BD70E2f2';

/** On-chain values the fake reader reports. Mutable, so a test can move the fee or the balance. */
export type FakePaymasterState = {
  postOpGasAllowance: bigint;
  penaltyBps: bigint;
  defaultFeeWei: bigint;
  feeOverrides: Map<string, bigint>;
  tenantBalances: Map<string, bigint>;
  tenantDeficits: Map<string, bigint>;
  registered: Set<string>;
  treasuryWei: bigint;
  depositWei: bigint;
  paused: boolean;
  /** Set to make every read throw, standing in for an unreachable chain. */
  unreachable: boolean;
};

export function createFakePaymasterState(): FakePaymasterState {
  return {
    postOpGasAllowance: 40_000n,
    penaltyBps: 1000n,
    defaultFeeWei: 100_000_000_000_000n,
    feeOverrides: new Map(),
    tenantBalances: new Map(),
    tenantDeficits: new Map(),
    registered: new Set(),
    treasuryWei: 0n,
    depositWei: 0n,
    paused: false,
    unreachable: false,
  };
}

/**
 * A `PaymasterReader` backed by a plain object rather than a chain.
 *
 * Deliberately not a mock of the *contract* — the contract's own behaviour is covered by the
 * Foundry suite, and the TypeScript↔Solidity boundary by `scripts/verify-authorisation.ts`. What
 * this stands in for is the *chain*, so that service and ledger tests can move a balance or a fee
 * without mining a block.
 */
export function createFakePaymasterReader(state: FakePaymasterState) {
  const guard = () => {
    if (state.unreachable) throw new Error('chain unreachable');
  };
  return {
    address: TEST_PAYMASTER_ADDRESS as `0x${string}`,
    async params() {
      guard();
      return { postOpGasAllowance: state.postOpGasAllowance, penaltyBps: state.penaltyBps, defaultFeeWei: state.defaultFeeWei };
    },
    async feeFor(tenantId: string) {
      guard();
      return state.feeOverrides.get(tenantId) ?? state.defaultFeeWei;
    },
    async tenant(tenantId: string) {
      guard();
      return {
        registered: state.registered.has(tenantId),
        enabled: true,
        withdrawAddress: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' as `0x${string}`,
        balanceWei: state.tenantBalances.get(tenantId) ?? 0n,
        deficitWei: state.tenantDeficits.get(tenantId) ?? 0n,
        feeWei: state.feeOverrides.get(tenantId) ?? state.defaultFeeWei,
      };
    },
    async treasury() {
      guard();
      return state.treasuryWei;
    },
    async deposit() {
      guard();
      return state.depositWei;
    },
    async isSigner() {
      guard();
      return true;
    },
    async paused() {
      guard();
      return state.paused;
    },
    async blockNumber() {
      return 100n;
    },
  };
}

export type SponsorshipTestContext = TestContext & { paymasterState: FakePaymasterState };

/** A stack with gas sponsorship enabled and the chain faked out. */
export async function startSponsorshipStack(envOverrides: Record<string, string> = {}): Promise<SponsorshipTestContext> {
  const container = await new PostgreSqlContainer('postgres:17-alpine').start();
  const databaseUrl = container.getConnectionUri();
  await runMigrations(databaseUrl);

  const chainState = createMockChainState();
  const rpc = await startMockRpc(chainState);
  const { fetchImpl, calls } = createMockBundlerFetch();
  const paymasterState = createFakePaymasterState();

  const config = loadConfig({
    NODE_ENV: 'test',
    GIANO_DEPLOYMENT_CLASS: 'development',
    LOG_LEVEL: 'error',
    DATABASE_URL: databaseUrl,
    TENANTS_SEED: tenantSeedJson,
    CHAIN_ID: '31337',
    RPC_URL: rpc.url,
    BUNDLER_URL: 'http://bundler.test',
    ENTRYPOINT_ADDRESS: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
    FACTORY_ADDRESS: '0x2222222222222222222222222222222222222222',
    CEREMONY_RATE_LIMIT_PER_MINUTE: '1000',
    USEROP_RATE_LIMIT_PER_MINUTE: '1000',
    SPONSORSHIP_ENABLED: 'true',
    SPONSORSHIP_PAYMASTER_ADDRESS: TEST_PAYMASTER_ADDRESS,
    SPONSORSHIP_SIGNER_KIND: 'local',
    SPONSORSHIP_SIGNER_KEY_REF: TEST_SPONSORSHIP_SIGNER_KEY,
    SPONSORSHIP_RATE_LIMIT_PER_MINUTE: '10000',
    ...envOverrides,
  } as NodeJS.ProcessEnv);

  const { db, pool } = createDb(databaseUrl);
  await seedTenants(db, config.TENANTS_SEED);
  const app = await buildApp({ config, db, fetchImpl, paymasterReader: createFakePaymasterReader(paymasterState) });
  return { container, db, pool, rpc, config, app, bundlerCalls: calls, chainState, paymasterState };
}
