import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { operatorHistory, operators } from '../src/db/schema.js';
import { bootstrapOperators, createOperatorService } from '../src/services/operators.js';
import { OPERATOR, OPERATOR_ENV, operatorSignIn, SECOND_OPERATOR, startTestStack, stopTestStack, STRANGER, type TestContext } from './setup.js';

/**
 * The operators as rows (specs/OPERATOR-ADMIN-SPECS.md §4.1, openspec change operators-in-database):
 * seeded once per environment into an empty table, managed by the operators from then on, with
 * every change recorded and the deployment never left without an operator.
 */

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startTestStack(OPERATOR_ENV);
});

afterAll(async () => {
  await stopTestStack(ctx);
});

const as = async (token: string, method: 'GET' | 'POST' | 'DELETE', url: string, payload?: object) =>
  ctx.app.inject({ method, url, headers: { authorization: `Bearer ${token}` }, ...(payload ? { payload } : {}) });

describe('bootstrap', () => {
  it('writes nothing into a table that already has an operator', async () => {
    expect(await bootstrapOperators(ctx.db, 'dev', [{ id: 'intruder', address: STRANGER.address }])).toEqual([]);
    expect(await ctx.db.select().from(operators).where(eq(operators.id, 'intruder'))).toEqual([]);
  });

  it('seeds an empty table once, recording each as bootstrap, even from replicas booting together', async () => {
    const saved = await ctx.db.select().from(operators);
    await ctx.db.delete(operators);
    try {
      const seeds = [{ id: 'giovanni', address: '0xFebBB1e5b6D66E6281d0d4d4816f76B69365a09d' as const }];
      const results = await Promise.all([bootstrapOperators(ctx.db, 'dev', seeds), bootstrapOperators(ctx.db, 'dev', seeds)]);
      expect(results.flat()).toEqual(['giovanni']);
      const [row] = await ctx.db.select().from(operators);
      expect(row).toMatchObject({ id: 'giovanni', address: '0xfebbb1e5b6d66e6281d0d4d4816f76b69365a09d', addedBy: 'bootstrap:dev' });
      const history = await ctx.db.select().from(operatorHistory).where(eq(operatorHistory.operatorId, 'giovanni'));
      expect(history.map((h) => [h.action, h.actor])).toEqual([['bootstrap', 'bootstrap:dev']]);
    } finally {
      await ctx.db.delete(operators);
      await ctx.db.insert(operators).values(saved);
    }
  });
});

describe('managing operators from the console', () => {
  it('adds an operator who can sign in at once, and records who added them', async () => {
    const token = await operatorSignIn(ctx.app, OPERATOR);
    const added = await as(token, 'POST', '/v1/operator/operators', { id: 'ops-new', address: STRANGER.address });
    expect(added.statusCode).toBe(201);
    expect(added.json()).toMatchObject({ id: 'ops-new', address: STRANGER.address.toLowerCase(), addedBy: `operator:ops-test:${OPERATOR.address.toLowerCase()}` });
    await expect(operatorSignIn(ctx.app, STRANGER)).resolves.toMatch(/^gos_/);

    const list = await as(token, 'GET', '/v1/operator/operators');
    expect(list.json().operators.map((o: { id: string }) => o.id)).toEqual(['ops-second', 'ops-test', 'ops-new']);
  });

  it('refuses a duplicate id or address, and a malformed one', async () => {
    const token = await operatorSignIn(ctx.app, OPERATOR);
    const byId = await as(token, 'POST', '/v1/operator/operators', { id: 'ops-test', address: `0x${'c'.repeat(40)}` });
    expect(byId.statusCode).toBe(409);
    expect(byId.json()).toMatchObject({ error: 'conflict', field: 'id' });
    const byAddress = await as(token, 'POST', '/v1/operator/operators', { id: 'ops-dup', address: OPERATOR.address.toUpperCase().replace('0X', '0x') });
    expect(byAddress.json()).toMatchObject({ error: 'conflict', field: 'address' });
    expect((await as(token, 'POST', '/v1/operator/operators', { id: 'Has Spaces', address: `0x${'c'.repeat(40)}` })).statusCode).toBe(400);
  });

  it('removes an operator, ending their sessions at once; never yourself', async () => {
    const token = await operatorSignIn(ctx.app, OPERATOR);
    const theirs = await operatorSignIn(ctx.app, STRANGER);

    const self = await as(token, 'DELETE', '/v1/operator/operators/ops-test');
    expect(self.statusCode).toBe(409);
    expect(self.json().error).toBe('self-removal');

    expect((await as(token, 'DELETE', '/v1/operator/operators/ops-new')).statusCode).toBe(204);
    expect((await as(theirs, 'GET', '/v1/operator/operators')).statusCode).toBe(401);
    expect((await as(token, 'DELETE', '/v1/operator/operators/ops-new')).statusCode).toBe(404);

    const history = (await as(token, 'GET', '/v1/operator/operators/history')).json().entries;
    expect(history.slice(0, 2).map((e: { action: string; operatorId: string }) => [e.action, e.operatorId])).toEqual([
      ['remove', 'ops-new'],
      ['add', 'ops-new'],
    ]);
  });

  it('never removes the last operator', async () => {
    const service = createOperatorService(ctx.db);
    const saved = await ctx.db.select().from(operators);
    await ctx.db.delete(operators).where(eq(operators.id, 'ops-second'));
    try {
      const outsider = { id: 'ops-gone', address: STRANGER.address.toLowerCase(), sessionId: (await ctx.db.execute(sql`SELECT gen_random_uuid() AS id`)).rows[0].id as string };
      await expect(service.remove('ops-test', outsider)).rejects.toMatchObject({ code: 'last-operator' });
    } finally {
      await ctx.db.delete(operators);
      await ctx.db.insert(operators).values(saved);
    }
  });

  it('is an operator-only route: no session, no list', async () => {
    expect((await ctx.app.inject({ method: 'GET', url: '/v1/operator/operators' })).statusCode).toBe(401);
    expect(SECOND_OPERATOR.address).not.toBe(OPERATOR.address);
  });
});

describe('the init step', () => {
  it('refuses tenant fixtures outside a local stack, before touching the database', async () => {
    const run = promisify(execFile);
    const failure = await run('node_modules/.bin/tsx', ['src/init.ts'], {
      env: { ...process.env, DATABASE_URL: 'postgres://nobody@127.0.0.1:1/none', GIANO_ENVIRONMENT: 'dev', TENANT_FIXTURES: '[]' },
    }).catch((error: { code: number; stderr: string }) => error);
    expect(failure).toMatchObject({ code: 1, stderr: expect.stringContaining('"dev" is not a local stack') });
  });

  it('refuses an unknown environment', async () => {
    const run = promisify(execFile);
    const failure = await run('node_modules/.bin/tsx', ['src/init.ts'], {
      env: { ...process.env, DATABASE_URL: 'postgres://nobody@127.0.0.1:1/none', GIANO_ENVIRONMENT: 'staging' },
    }).catch((error: { code: number; stderr: string }) => error);
    expect(failure).toMatchObject({ code: 1, stderr: expect.stringContaining('GIANO_ENVIRONMENT must be one of') });
  });
});
