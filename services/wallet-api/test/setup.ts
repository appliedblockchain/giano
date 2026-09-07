import * as http from 'node:http';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { buildApp } from '../src/app.js';
import { loadConfig, type AppConfig } from '../src/config.js';
import { createDb, type Db } from '../src/db/index.js';
import { runMigrations } from '../src/migrate.js';

export const TEST_WALLET_ADDRESS = '0x1111111111111111111111111111111111111234';
export const TEST_ORIGIN = 'http://localhost:4000';
export const TEST_RP_ID = 'localhost';
export const ADMIN_KEY = 'test-admin-key';

/** Tiny JSON-RPC stub standing in for the chain RPC: factory.getAddress → fixed address. */
export function startMockRpc(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      const { id, method } = JSON.parse(body) as { id: number; method: string };
      const result =
        method === 'eth_call'
          ? `0x${TEST_WALLET_ADDRESS.slice(2).padStart(64, '0')}`
          : method === 'eth_chainId'
            ? '0x7a69'
            : '0x0';
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

export type BundlerCall = { method: string; params: unknown[] };

/** Fetch stub for the bundler URL, recording calls and answering with canned results. */
export function createMockBundlerFetch(results: Record<string, unknown> = {}) {
  const calls: BundlerCall[] = [];
  const fetchImpl: typeof fetch = async (_url, init) => {
    const { id, method, params } = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] };
    calls.push({ method, params });
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
};

export async function startTestStack(envOverrides: Record<string, string> = {}): Promise<TestContext> {
  const container = await new PostgreSqlContainer('postgres:17-alpine').start();
  const databaseUrl = container.getConnectionUri();
  await runMigrations(databaseUrl);

  const rpc = await startMockRpc();
  const { fetchImpl, calls } = createMockBundlerFetch();

  const config = loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'error',
    DATABASE_URL: databaseUrl,
    RP_ID: TEST_RP_ID,
    RP_NAME: 'Giano Test',
    EXPECTED_ORIGINS: TEST_ORIGIN,
    CHAIN_ID: '31337',
    RPC_URL: rpc.url,
    BUNDLER_URL: 'http://bundler.test',
    ENTRYPOINT_ADDRESS: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
    FACTORY_ADDRESS: '0x2222222222222222222222222222222222222222',
    OPEN_REGISTRATION: 'true',
    ADMIN_API_KEYS: ADMIN_KEY,
    CEREMONY_RATE_LIMIT_PER_MINUTE: '1000',
    ...envOverrides,
  } as NodeJS.ProcessEnv);

  const { db, pool } = createDb(databaseUrl);
  const app = await buildApp({ config, db, fetchImpl });
  return { container, db, pool, rpc, config, app, bundlerCalls: calls };
}

export async function stopTestStack(ctx: TestContext): Promise<void> {
  await ctx.app.close();
  await ctx.pool.end();
  await ctx.rpc.close();
  await ctx.container.stop();
}
