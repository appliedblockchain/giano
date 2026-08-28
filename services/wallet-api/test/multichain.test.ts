import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CANONICAL_FACTORY, CANONICAL_IMPLEMENTATION } from '@appliedblockchain/giano-contracts';
import type { PublicClient } from 'viem';
import { loadConfig } from '../src/config.js';
import chainPlugin from '../src/plugins/chain.js';
import type { ChainRegistry, ChainServices } from '../src/services/chains.js';
import { isFatalFailure, verifyChain } from '../src/services/chain-verify.js';
import { startTestStack, stopTestStack, TENANT_A, type TestContext } from './setup.js';
import { createAuthenticator, makeRegistrationResponse } from './webauthn-fixtures.js';

const BASE_ENV = {
  NODE_ENV: 'test',
  GIANO_DEPLOYMENT_CLASS: 'development',
  LOG_LEVEL: 'error',
  DATABASE_URL: 'postgres://u:p@localhost:5432/x',
} as NodeJS.ProcessEnv;

describe('config: the chain list', () => {
  it('normalises the single-chain scalar shorthand into a one-entry list (MC-47, MC-132)', () => {
    const config = loadConfig({
      ...BASE_ENV,
      CHAIN_ID: '31337',
      RPC_URL: 'http://a:8545',
      BUNDLER_URL: 'http://a:4337',
      ENTRYPOINT_ADDRESS: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
      FACTORY_ADDRESS: '0x2222222222222222222222222222222222222222',
      USEROP_ALLOWED_PAYMASTERS: '0x1000000000000000000000000000000000000001',
    });
    expect(config.CHAINS).toHaveLength(1);
    expect(config.CHAINS[0]).toMatchObject({
      chainId: 31337,
      rpcUrl: 'http://a:8545',
      bundlerUrl: 'http://a:4337',
      factory: '0x2222222222222222222222222222222222222222',
    });
    // address-valued env defaults fold into the sole chain's policy (MC-61)
    expect(config.CHAINS[0].policy.allowedPaymasters).toEqual(['0x1000000000000000000000000000000000000001']);
    expect(config.CHAINS[0].name).not.toMatch(/^\d+$/); // never a bare number (MC-81)
  });

  it('accepts GIANO_CHAINS, resolving registry defaults per chain (MC-46)', () => {
    const config = loadConfig({
      ...BASE_ENV,
      GIANO_CHAINS: JSON.stringify([
        { chainId: 8453, name: 'Base', rpcUrl: 'http://a:8545', bundlerUrl: 'http://a:4337' },
        {
          chainId: 31338,
          name: 'Devnet B',
          rpcUrl: 'http://b:8545',
          bundlerUrl: 'http://b:4337',
          entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
          factory: CANONICAL_FACTORY,
        },
      ]),
    });
    expect(config.CHAINS.map((chain) => chain.chainId)).toEqual([8453, 31338]);
    // Base's addresses default from the contracts registry — which is canonical-only now
    expect(config.CHAINS[0].factory).toBe(CANONICAL_FACTORY);
  });

  it('refuses BOTH the shorthand and GIANO_CHAINS — never a merge (§3.4)', () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        CHAIN_ID: '31337',
        RPC_URL: 'http://a:8545',
        BUNDLER_URL: 'http://a:4337',
        GIANO_CHAINS: '[]',
      }),
    ).toThrow(/mutually exclusive/);
  });

  it('refuses a configuration that names no chain at all', () => {
    expect(() => loadConfig({ ...BASE_ENV })).toThrow(/GIANO_CHAINS.*or CHAIN_ID/s);
  });

  it('refuses duplicate chain ids', () => {
    const entry = {
      chainId: 31337,
      name: 'A',
      rpcUrl: 'http://a:8545',
      bundlerUrl: 'http://a:4337',
      entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
      factory: CANONICAL_FACTORY,
    };
    expect(() => loadConfig({ ...BASE_ENV, GIANO_CHAINS: JSON.stringify([entry, entry]) })).toThrow(/duplicate chainId/);
  });

  it('refuses chain-agnostic address-valued env vars alongside GIANO_CHAINS (MC-61)', () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        GIANO_CHAINS: JSON.stringify([
          {
            chainId: 31337,
            name: 'A',
            rpcUrl: 'http://a:8545',
            bundlerUrl: 'http://a:4337',
            entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
            factory: CANONICAL_FACTORY,
          },
        ]),
        USEROP_ALLOWED_TARGETS: '0x1000000000000000000000000000000000000001',
      }),
    ).toThrow(/USEROP_ALLOWED_TARGETS is single-chain shorthand/);
  });
});

// ── requireChain: per-request resolution (MC-51–MC-55, §9.3) ─────────────────────

function fakeChain(chainId: number, status: 'ready' | 'unavailable' = 'ready'): ChainServices {
  return { chainId, status, descriptor: { chainId } } as unknown as ChainServices;
}

function fakeRegistry(chains: ChainServices[]): ChainRegistry {
  const byId = new Map(chains.map((chain) => [chain.chainId, chain]));
  return {
    get: (chainId) => {
      const chain = byId.get(chainId);
      if (!chain) throw new Error('unknown');
      return chain;
    },
    tryGet: (chainId) => byId.get(chainId),
    get sole() {
      if (chains.length !== 1) throw new Error('sole with several chains');
      return chains[0];
    },
    get all() {
      return chains;
    },
    get size() {
      return chains.length;
    },
    servedChainIds: () => chains.map((chain) => chain.chainId),
    anyReady: () => chains.find((chain) => chain.status === 'ready')!,
  };
}

async function appWithChains(chains: ChainServices[]) {
  const app = Fastify({ logger: false });
  await app.register(chainPlugin, { registry: fakeRegistry(chains) });
  app.post('/probe', { preHandler: app.requireChain }, async (request) => ({ resolved: request.chain!.chainId }));
  return app;
}

describe('requireChain', () => {
  it('resolves a named, served chain', async () => {
    const app = await appWithChains([fakeChain(31337), fakeChain(31338)]);
    const response = await app.inject({ method: 'POST', url: '/probe', payload: { chainId: 31338 } });
    expect(response.json()).toEqual({ resolved: 31338 });
  });

  it('applies an omitted chain to the sole configured chain (MC-53)', async () => {
    const app = await appWithChains([fakeChain(31337)]);
    const response = await app.inject({ method: 'POST', url: '/probe', payload: {} });
    expect(response.json()).toEqual({ resolved: 31337 });
  });

  it('refuses omission as ambiguous when several chains are served — never guesses (MC-53)', async () => {
    const app = await appWithChains([fakeChain(31337), fakeChain(31338)]);
    const response = await app.inject({ method: 'POST', url: '/probe', payload: {} });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'chain-required', servedChainIds: [31337, 31338] });
  });

  it('refuses an unserved chain with a distinct, machine-readable reason (MC-52)', async () => {
    const app = await appWithChains([fakeChain(31337)]);
    const response = await app.inject({ method: 'POST', url: '/probe', payload: { chainId: 10 } });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'unsupported-chain', servedChainIds: [31337] });
  });

  it('distinguishes "not served" (permanent) from "temporarily unavailable" (retryable) (MC-55)', async () => {
    const app = await appWithChains([fakeChain(31337), fakeChain(31338, 'unavailable')]);
    const response = await app.inject({ method: 'POST', url: '/probe', payload: { chainId: 31338 } });
    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: 'chain-unavailable' });
  });

  it('reads the ERC-7677 chain from params[2]', async () => {
    const app = await appWithChains([fakeChain(31337), fakeChain(31338)]);
    const response = await app.inject({ method: 'POST', url: '/probe', payload: { params: [{}, '0x', '0x7a6a'] } });
    expect(response.json()).toEqual({ resolved: 31338 });
  });
});

// ── verifyChain: the boot-time gate (§3.5, §4.2) ─────────────────────────────────

type FakeClientBehaviour = {
  chainId?: number | Error;
  code?: Record<string, string>;
  implementation?: string;
  probeAddress?: string;
};

function fakeClient(behaviour: FakeClientBehaviour): PublicClient {
  return {
    async getChainId() {
      if (behaviour.chainId instanceof Error) throw behaviour.chainId;
      return behaviour.chainId ?? 31337;
    },
    async getCode({ address }: { address: string }) {
      return behaviour.code?.[address.toLowerCase()] ?? '0xabcd';
    },
    async readContract({ functionName }: { functionName: string }) {
      if (functionName === 'implementation') return behaviour.implementation ?? CANONICAL_IMPLEMENTATION;
      if (functionName === 'getAddress') return behaviour.probeAddress ?? '0x00000000000000000000000000000000000abcde';
      throw new Error(`unexpected read: ${functionName}`);
    },
  } as unknown as PublicClient;
}

const descriptor = {
  chainId: 31337,
  name: 'A',
  rpcUrl: 'http://a',
  bundlerUrl: 'http://a-b',
  entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as const,
  factory: CANONICAL_FACTORY,
  policy: { allowedTargets: [], allowedPaymasters: [] },
};

describe('verifyChain', () => {
  it('passes a healthy canonical chain', async () => {
    const result = await verifyChain(descriptor, fakeClient({}));
    expect(result.failures).toEqual([]);
    expect(result.factoryAddressCanonical).toBe(true);
    expect(result.probeAddress).toBeTruthy();
  });

  it('an endpoint reporting a different chain id is FATAL (MC-49)', async () => {
    const result = await verifyChain(descriptor, fakeClient({ chainId: 31338 }));
    expect(result.failures).toEqual([{ kind: 'chain-id-mismatch', declared: 31337, reported: 31338 }]);
    expect(result.failures.every(isFatalFailure)).toBe(true);
  });

  it('an unreachable endpoint is NOT fatal — the deployment starts and retries (MC-54, MC-92)', async () => {
    const result = await verifyChain(descriptor, fakeClient({ chainId: new Error('connect ECONNREFUSED') }));
    expect(result.reachable).toBe(false);
    expect(result.failures).toHaveLength(1);
    expect(isFatalFailure(result.failures[0])).toBe(false);
  });

  it('a non-canonical factory address is FATAL — the admission gate (MC-19, MC-20)', async () => {
    const divergent = { ...descriptor, factory: '0x3451C87749FE28Af2995f644aBc8d5B1c61A6191' as `0x${string}` };
    const result = await verifyChain(divergent, fakeClient({}));
    expect(result.failures.some((failure) => failure.kind === 'factory-not-canonical')).toBe(true);
    expect(result.failures.filter(isFatalFailure).length).toBeGreaterThan(0);
  });

  it('a canonical factory running DIFFERENT code fails the implementation cross-check (MC-22)', async () => {
    const result = await verifyChain(descriptor, fakeClient({ implementation: '0x9999999999999999999999999999999999999999' }));
    expect(result.failures.some((failure) => failure.kind === 'implementation-mismatch')).toBe(true);
  });

  it('a missing EntryPoint is FATAL (MC-141)', async () => {
    const result = await verifyChain(
      descriptor,
      fakeClient({ code: { [descriptor.entryPoint.toLowerCase()]: '0x' } }),
    );
    expect(result.failures.some((failure) => failure.kind === 'entrypoint-missing')).toBe(true);
  });
});

// ── The relay against a TWO-chain registry (testcontainers) ─────────────────────

describe('two-chain relay', () => {
  let ctx: TestContext;
  let sessionToken: string;
  let walletAddress: string;

  const CHAIN_A_BUNDLER = 'http://bundler-a.test';
  const CHAIN_B_BUNDLER = 'http://bundler-b.test';

  beforeAll(async () => {
    ctx = await startTestStack({
      GIANO_CHAINS: JSON.stringify([
        {
          chainId: 31337,
          name: 'Devnet A',
          // both point at the same mock RPC; the mock answers eth_chainId 0x7a69 (31337),
          // which only chain A declares — chain B is left structurally unverified here
          // because buildApp does not verify (index.ts does), and the relay path is what
          // this suite exercises
          rpcUrl: 'http://rpc-a.invalid',
          bundlerUrl: CHAIN_A_BUNDLER,
          entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
          factory: '0x2222222222222222222222222222222222222222',
        },
        {
          chainId: 31338,
          name: 'Devnet B',
          rpcUrl: 'http://rpc-b.invalid',
          bundlerUrl: CHAIN_B_BUNDLER,
          entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
          factory: '0x2222222222222222222222222222222222222222',
        },
      ]),
    });
    // point chain A's read path at the live mock RPC so registration derives an address
    // (the registry holds per-chain clients built from the descriptor URLs, so instead we
    // register through the sole ready path: patch the descriptor before first use)
    const chainA = ctx.app.chains.get(31337);
    (chainA as { publicClient: unknown }).publicClient = (await import('viem')).createPublicClient({
      transport: (await import('viem')).http(ctx.rpc.url),
    });

    const auth = createAuthenticator();
    const options = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_A.walletOrigin },
      payload: { externalUserId: 'multichain-user', kind: 'registration' },
    });
    expect(options.statusCode).toBe(200);
    const { challenge } = options.json() as { challenge: string };
    const verify = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      headers: { origin: TENANT_A.walletOrigin },
      payload: {
        externalUserId: 'multichain-user',
        response: makeRegistrationResponse(auth, { challenge, origin: TENANT_A.walletOrigin, rpId: TENANT_A.rpId }),
      },
    });
    expect(verify.statusCode).toBe(200);
    const body = verify.json() as { walletAddress: string; session: { token: string } };
    sessionToken = body.session.token;
    walletAddress = body.walletAddress;
  }, 120_000);

  afterAll(async () => {
    if (ctx) await stopTestStack(ctx);
  });

  const makeOp = (nonce: number) => ({
    sender: walletAddress,
    nonce: `0x${nonce.toString(16)}`,
    callData: '0x',
    callGasLimit: '0x30000',
    verificationGasLimit: '0x30000',
    preVerificationGas: '0x10000',
    maxFeePerGas: '0x3b9aca00',
    maxPriorityFeePerGas: '0x3b9aca00',
    signature: '0x1234',
  });

  it('routes each operation to ITS chain\'s bundler, and changing the chain changes the endpoint (MC-113, MC-58)', async () => {
    const onA = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { chainId: 31337, userOperation: makeOp(1) },
    });
    expect(onA.statusCode).toBe(200);
    const onB = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { chainId: 31338, userOperation: makeOp(1) },
    });
    expect(onB.statusCode).toBe(200);

    const sends = ctx.bundlerCalls.filter((call) => call.method === 'eth_sendUserOperation');
    expect(sends.map((call) => call.url)).toEqual([CHAIN_A_BUNDLER, CHAIN_B_BUNDLER]);

    // The SAME operation on two chains has two different hashes: the hash commits to the
    // resolved chain (MC-57), so a submission cannot be replayed across chains.
    const hashA = (onA.json() as { userOperationHash: string }).userOperationHash;
    const hashB = (onB.json() as { userOperationHash: string }).userOperationHash;
    expect(hashA).not.toBe(hashB);

    // The audit trail answers "which chain did this go to" directly (MC-59).
    const rowB = await ctx.app.inject({
      method: 'GET',
      url: `/v1/userops/${hashB}`,
      headers: { authorization: `Bearer ${sessionToken}` },
    });
    expect((rowB.json() as { chainId: number }).chainId).toBe(31338);
  });

  it('refuses an omitted chainId as ambiguous when several chains are served (MC-53)', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: makeOp(2) },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: 'chain-required', servedChainIds: [31337, 31338] });
  });

  it('refuses an unserved chain with the served list (MC-52)', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { chainId: 10, userOperation: makeOp(3) },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: 'unsupported-chain', servedChainIds: [31337, 31338] });
  });

  it('reports both chains on /v1/version, with no privileged one (MC-56)', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/v1/version' });
    const body = res.json() as { chainId: number | null; chains: Array<{ chainId: number }> };
    expect(body.chainId).toBeNull();
    expect(body.chains.map((chain) => chain.chainId)).toEqual([31337, 31338]);
  });
});
