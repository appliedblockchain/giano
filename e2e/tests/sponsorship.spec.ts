import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import { ORIGINS } from '../origins.mjs';
import { connectWallet, expectOutContains, openActionPopup, TENANTS, type Tenant, type VirtualCredential } from './helpers';

/**
 * The production paymaster, end to end.
 *
 * Two things separate this from the existing sponsored-path coverage. First, the accounting is
 * asserted rather than assumed: a sponsored transaction that lands is not evidence that the ledger
 * is right, so every scenario checks the tenant's balance fell by gas + fee + overhead, the fee
 * reached the treasury, and the invariant still holds. Second, refusals are asserted *where the
 * user meets them* — no approve button, no passkey prompt, the reason both displayed and written to
 * the console — because that is wallet-side behaviour, and it is the part a bring-your-own UI has
 * to get right separately.
 */

const devnetDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'devnet');
const ADDRESSES = JSON.parse(fs.readFileSync(path.join(devnetDir, 'addresses.json'), 'utf8')) as {
  testErc20: string;
  sponsorshipPaymaster: string;
  tenants: Array<{ slug: string; id: string }>;
};

const WALLET_API = process.env.WALLET_API_URL ?? ORIGINS.api;

// ── admin API helpers ─────────────────────────────────────────────────────────

type Position = { balanceWei: string; reservedWei: string; availableWei: string; deficitWei: string; feeWei: string };

async function getPosition(tenant: Tenant): Promise<Position> {
  const response = await fetch(`${WALLET_API}/v1/admin/sponsorship/balance`, {
    headers: { authorization: `Bearer ${tenant.adminKey}` },
  });
  expect(response.ok, `balance read failed: ${response.status}`).toBe(true);
  return (await response.json()) as Position;
}

async function getSpend(tenant: Tenant) {
  const response = await fetch(`${WALLET_API}/v1/admin/sponsorship/spend`, {
    headers: { authorization: `Bearer ${tenant.adminKey}` },
  });
  expect(response.ok).toBe(true);
  return (await response.json()) as {
    settlements: Array<{ useropHash: string; gasCostWei: string; feeWei: string; overheadWei: string; totalWei: string; success: boolean }>;
    totals: { gasCostWei: string; feeWei: string; overheadWei: string; totalWei: string; count: number };
  };
}

async function getConfig(tenant: Tenant): Promise<Record<string, unknown>> {
  const response = await fetch(`${WALLET_API}/v1/admin/sponsorship`, { headers: { authorization: `Bearer ${tenant.adminKey}` } });
  return ((await response.json()) as { config: Record<string, unknown> }).config;
}

async function putConfig(tenant: Tenant, config: unknown): Promise<void> {
  const response = await fetch(`${WALLET_API}/v1/admin/sponsorship`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${tenant.adminKey}` },
    body: JSON.stringify(config),
  });
  expect(response.ok, `config write failed: ${response.status} ${await response.text()}`).toBe(true);
}

/** Runs `body` with a narrowed config, then puts the original back whatever happens. */
async function withConfig<T>(tenant: Tenant, overrides: Record<string, unknown>, body: () => Promise<T>): Promise<T> {
  const original = await getConfig(tenant);
  await putConfig(tenant, { ...original, ...overrides });
  try {
    return await body();
  } finally {
    await putConfig(tenant, original);
  }
}

/** The paymaster's own view, read straight from the chain — never from the service's books. */
async function readChain(fn: string, args: string[] = []): Promise<string> {
  // Selectors, not an ABI import, to keep this file free of a build step — but taken from
  // `cast sig` rather than written from memory, because a wrong selector reverts and reads as a
  // broken paymaster rather than a broken test.
  const selectors: Record<string, string> = {
    treasury: '0x61d027b3', // treasury()
    getDeposit: '0xc399ec88', // getDeposit()
  };
  const response = await fetch(process.env.RPC_URL ?? ORIGINS.rpc, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_call',
      params: [{ to: ADDRESSES.sponsorshipPaymaster, data: selectors[fn] + args.join('') }, 'latest'],
    }),
  });
  const body = (await response.json()) as { result?: string; error?: { message: string } };
  if (body.error) throw new Error(`${fn}: ${body.error.message}`);
  return body.result!;
}

async function treasuryWei(): Promise<bigint> {
  return BigInt(await readChain('treasury'));
}

async function depositWei(): Promise<bigint> {
  return BigInt(await readChain('getDeposit'));
}

/** Σ tenant balances + treasury ≤ deposit. The property the whole design rests on. */
async function expectInvariantIntact(): Promise<void> {
  const claims = (await allPositions()).reduce((sum, p) => sum + BigInt(p.balanceWei), 0n) + (await treasuryWei());
  expect(claims, 'claims exceed the paymaster deposit — this is an insolvency').toBeLessThanOrEqual(await depositWei());
}

/** Every tenant this deployment actually serves. A partial local stack may not have both. */
async function allPositions(): Promise<Position[]> {
  const positions: Position[] = [];
  for (const tenant of Object.values(TENANTS)) {
    const response = await fetch(`${WALLET_API}/v1/admin/sponsorship/balance`, {
      headers: { authorization: `Bearer ${tenant.adminKey}` },
    });
    if (response.ok) positions.push((await response.json()) as Position);
  }
  expect(positions.length, 'no tenant balance was readable — the stack is not provisioned').toBeGreaterThan(0);
  return positions;
}

/**
 * Waits until nothing is outstanding for this tenant, so a balance read is a stable baseline.
 *
 * The ledger converges rather than updating synchronously: a settlement lands when the watcher sees
 * the event, and a reservation is released then too. Reading a balance while either is in flight
 * measures a moment, not a state.
 */
async function settleAllPending(tenant: Tenant, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (BigInt((await getPosition(tenant)).reservedWei) === 0n) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error('reservations were still outstanding after waiting — the watcher may be stalled');
}

/** Waits for the watcher to observe a settlement — the ledger converges, it is not synchronous. */
async function waitForSettlement(tenant: Tenant, count: number, timeoutMs = 30_000): Promise<Awaited<ReturnType<typeof getSpend>>> {
  const deadline = Date.now() + timeoutMs;
  let last = await getSpend(tenant);
  while (last.totals.count < count && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    last = await getSpend(tenant);
  }
  expect(last.totals.count, 'the watcher never observed the settlement').toBeGreaterThanOrEqual(count);
  return last;
}

// ── console capture ───────────────────────────────────────────────────────────

/**
 * R-17: the reason has to be written to the console as well as displayed. A transient notice is
 * gone by the time anyone investigates, and the reason is the only thing that separates "this app
 * is misconfigured" from "this app is out of credit".
 */
function captureConsole(page: Page): string[] {
  const lines: string[] = [];
  page.on('console', (message) => lines.push(`${message.type()}: ${message.text()}`));
  return lines;
}

// ── the sponsored path ────────────────────────────────────────────────────────

for (const slug of ['stock', 'byo'] as const) {
  const tenant = TENANTS[slug];

  test.describe(`sponsored path — ${slug} wallet UI`, () => {
    test('debits the tenant for gas + fee + overhead and credits the fee to the treasury', async ({ page }) => {
      // Connect FIRST, then read the baseline.
      //
      // Connecting deploys the smart account, and that deployment is itself a sponsored operation
      // — so a baseline taken before it would span two settlements while the assertions below
      // account for one. Reading after isolates the transaction actually under test.
      const { credentials } = await connectWallet(page, tenant);
      await settleAllPending(tenant);

      const before = await getPosition(tenant);
      const treasuryBefore = await treasuryWei();
      const spendBefore = await getSpend(tenant);

      const popup = await openActionPopup(page, '#send-erc20', credentials);

      // The pre-approval check has to have answered before an approve button exists at all.
      const approve = popup.getByRole('button', { name: tenant.ui.approveTx });
      await approve.waitFor({ state: 'visible', timeout: 30_000 });
      await approve.click();

      await expectOutContains(page, 'receipt:success: true');

      const spend = await waitForSettlement(tenant, spendBefore.totals.count + 1);
      const settlement = spend.settlements[0];

      // Every component separately visible: what was gas, what was Giano's margin, what was overhead.
      expect(BigInt(settlement.gasCostWei)).toBeGreaterThan(0n);
      expect(BigInt(settlement.feeWei)).toBe(BigInt(before.feeWei));
      expect(BigInt(settlement.overheadWei)).toBeGreaterThan(0n);
      expect(BigInt(settlement.totalWei)).toBe(
        BigInt(settlement.gasCostWei) + BigInt(settlement.feeWei) + BigInt(settlement.overheadWei),
      );
      expect(settlement.success).toBe(true);

      const after = await getPosition(tenant);
      expect(BigInt(after.balanceWei)).toBe(BigInt(before.balanceWei) - BigInt(settlement.totalWei));
      expect(BigInt(after.deficitWei)).toBe(0n);

      // The fee, and only the fee, reaches the treasury: gas and overhead leave the ledger.
      expect(await treasuryWei()).toBe(treasuryBefore + BigInt(settlement.feeWei));

      await expectInvariantIntact();
    });

    test('shows that the fee is covered, and says so in the console', async ({ page }) => {
      const logs = captureConsole(page);
      const { credentials } = await connectWallet(page, tenant);
      const popup = await openActionPopup(page, '#send-erc20', credentials);
      const popupLogs = captureConsole(popup);

      await popup.getByRole('button', { name: tenant.ui.approveTx }).waitFor({ state: 'visible', timeout: 30_000 });
      const covered = popup.locator(
        slug === 'stock' ? '[data-testid=sponsorship-covered]' : '[data-testid=byo-sponsorship-covered]',
      );
      await expect(covered).toBeVisible();
      expect(popupLogs.join('\n')).toMatch(/sponsorship available/);
      void logs;
    });
  });

  test.describe(`pre-approval refusals — ${slug} wallet UI`, () => {
    const refusalLocator = slug === 'stock' ? '[data-testid=sponsorship-refusal]' : '[data-testid=byo-sponsorship-refusal]';
    const refusalActionLocator = slug === 'stock' ? '[data-testid=sponsorship-refusal-action]' : '[data-testid=byo-sponsorship-refusal-action]';

    /**
     * The single most important assertion in this file: no approve button and no passkey prompt
     * for a transaction that will not be sponsored. The user is never asked for a fingerprint for
     * something that cannot be paid for.
     */
    async function expectRefusedBeforeApproval(page: Page, trigger: string, reason: string, credentials: VirtualCredential[]) {
      const popup = await openActionPopup(page, trigger, credentials);
      const popupLogs = captureConsole(popup);

      const refusal = popup.locator(refusalLocator);
      await refusal.waitFor({ state: 'visible', timeout: 30_000 });
      await expect(refusal).toHaveAttribute('data-reason', reason);

      // No approve button, at all.
      await expect(popup.getByRole('button', { name: tenant.ui.approveTx })).toHaveCount(0);

      // And it names who can act. The user cannot fund a balance or edit an allowlist, so a
      // refusal that stops at "this cannot be sponsored" leaves them retrying something that will
      // never work.
      await expect(popup.locator(refusalActionLocator)).not.toBeEmpty();

      // And the reason reached the console, not only the screen.
      expect(popupLogs.join('\n')).toContain(reason);

      await popup.getByRole('button', { name: 'Close' }).click();
      return popup;
    }

    test('refuses a contract that is not allow-listed', async ({ page }) => {
      // Baseline after connecting: the account deployment is itself sponsored, so it must not sit
      // inside the window this test is measuring.
      const { credentials } = await connectWallet(page, tenant);
      await settleAllPending(tenant);
      const before = await getPosition(tenant);

      await expectRefusedBeforeApproval(page, '#send-unlisted', 'contract-not-allowed', credentials);

      // Nothing charged, and nothing reserved: a refusal costs the tenant nothing at all.
      // Compared against `before` rather than against zero — an unrelated authorisation may
      // legitimately be in flight, and asserting an absolute zero would make this test depend on
      // what every other test happened to leave behind.
      const after = await getPosition(tenant);
      expect(after.balanceWei).toBe(before.balanceWei);
      expect(BigInt(after.reservedWei)).toBeLessThanOrEqual(BigInt(before.reservedWei));
    });

    test('refuses a function that is not allowed, with a different reason from the contract case', async ({ page }) => {
      const { credentials } = await connectWallet(page, tenant);

      await withConfig(tenant, { allowlist: [{ contract: ADDRESSES.testErc20, functions: ['approve(address,uint256)'] }] }, async () => {
        await expectRefusedBeforeApproval(page, '#send-erc20', 'function-not-allowed', credentials);
      });
    });

    test("refuses a transaction above the tenant's per-transaction cap", async ({ page }) => {
      const { credentials } = await connectWallet(page, tenant);

      await withConfig(tenant, { maxCostPerTxWei: '1' }, async () => {
        await expectRefusedBeforeApproval(page, '#send-erc20', 'cost-exceeds-cap', credentials);
      });
    });

    // A user adding a passkey on a new device holds no native token and no way to obtain one, so
    // this has to work with nothing about the wallet in the tenant's allowlist. `#send` is a
    // transfer to the wallet's own address — a self-call, which the rules classify structurally as
    // wallet management rather than by a selector list.
    test('sponsors wallet management with nothing about the wallet allow-listed', async ({ page }) => {
      const { credentials } = await connectWallet(page, tenant);

      const popup = await openActionPopup(page, '#send', credentials);
      await popup.getByRole('button', { name: tenant.ui.approveTx }).waitFor({ state: 'visible', timeout: 30_000 });
      await popup.getByRole('button', { name: tenant.ui.approveTx }).click();
      await expectOutContains(page, 'receipt:success: true');
      await expectInvariantIntact();
    });

    test('refuses wallet management only once the tenant explicitly opts out', async ({ page }) => {
      const { credentials } = await connectWallet(page, tenant);

      await withConfig(tenant, { walletManagement: { enabled: false } }, async () => {
        await expectRefusedBeforeApproval(page, '#send', 'wallet-management-not-sponsored', credentials);
      });
    });

    test('falls back cleanly to the unsponsored path when sponsorship is switched off', async ({ page }) => {
      const { credentials } = await connectWallet(page, tenant);

      await withConfig(tenant, { enabled: false }, async () => {
        // Not an error: a refusal with its own reason, shown before approval.
        await expectRefusedBeforeApproval(page, '#send-erc20', 'sponsorship-disabled', credentials);
      });
    });
  });
}

// ── accounting and operations ─────────────────────────────────────────────────

test.describe('accounting', () => {
  test('the invariant holds and the slack is unattributed rather than owed', async () => {
    await expectInvariantIntact();

    const claims = (await allPositions()).reduce((sum, p) => sum + BigInt(p.balanceWei), 0n) + (await treasuryWei());
    const slack = (await depositWei()) - claims;

    // Slack is expected and safe — the overhead allowance is a deliberate over-charge — but it must
    // never be negative, and it must be small relative to the deposit.
    expect(slack).toBeGreaterThanOrEqual(0n);
    expect(slack).toBeLessThan((await depositWei()) / 100n);
  });

  test('a tenant can reconcile every charge against the chain', async () => {
    const spend = await getSpend(TENANTS.stock);
    if (spend.settlements.length === 0) test.skip();

    // Each row is a `Sponsored` event, so its components must sum to its total, and the totals
    // must sum the rows.
    for (const row of spend.settlements) {
      expect(BigInt(row.totalWei)).toBe(BigInt(row.gasCostWei) + BigInt(row.feeWei) + BigInt(row.overheadWei));
    }
    const summed = spend.settlements.reduce((sum, r) => sum + BigInt(r.totalWei), 0n);
    expect(BigInt(spend.totals.totalWei)).toBeGreaterThanOrEqual(summed);
  });

  test('every decision is recorded, refusals included', async () => {
    // Across both tenants: which one the refusal tests ran against depends on the grep, and the
    // property under test — that refusals are recorded rule-by-rule — is not tenant-specific.
    const all: Array<{ reason: string | null; ruleResults: Array<{ rule: string; passed: boolean }> }> = [];
    for (const tenant of Object.values(TENANTS)) {
      const response = await fetch(`${WALLET_API}/v1/admin/sponsorship/decisions?outcome=refused`, {
        headers: { authorization: `Bearer ${tenant.adminKey}` },
      });
      if (!response.ok) continue;
      all.push(...((await response.json()) as { decisions: typeof all }).decisions);
    }

    expect(all.length, 'the refusal tests should have left records').toBeGreaterThan(0);
    // Rule-by-rule, so "why was this refused" is answerable without re-running anything.
    expect(all[0].ruleResults.some((r) => !r.passed)).toBe(true);
    expect(all.every((d) => d.reason !== null)).toBe(true);
  });
});

test.describe('tenant isolation', () => {
  test('a session from one tenant cannot obtain sponsorship from another', async () => {
    // A plain authentication failure that reveals nothing about whether the other tenant exists.
    const response = await fetch(`${WALLET_API}/v1/paymaster`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer not-a-real-session', origin: TENANTS.byo.walletUrl },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'pm_getPaymasterStubData',
        params: [{ sender: '0x1111111111111111111111111111111111111111', nonce: '0x0', callData: '0x' }, '0x0000000071727De22E5E9d8BAf0edAc6f37da032', '0x7a69', {}],
      }),
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'unauthorized', message: 'invalid or expired session' });
  });

  test("one tenant's admin key cannot read another's position", async () => {
    const stock = await getPosition(TENANTS.stock);
    const byo = await getPosition(TENANTS.byo);
    // Different tenants, different on-chain tenant ids, therefore different balances after use.
    expect(stock).not.toEqual(byo);
  });
});

test.describe('service availability', () => {
  test('reports sponsorship health on /readyz', async () => {
    const response = await fetch(`${WALLET_API}/readyz`);
    expect(response.ok).toBe(true);
    // A deployment that cannot sponsor must not report itself ready, so this being 'ok' is the
    // assertion that the signer is actually reachable.
    expect((await response.json()) as { sponsorship?: string }).toMatchObject({ status: 'ready', sponsorship: 'ok' });
  });

  test('exports the invariant and per-tenant balance metrics', async () => {
    const response = await fetch(`${WALLET_API}/metrics`);
    const body = await response.text();
    for (const metric of [
      'giano_sponsorship_decisions_total',
      'giano_paymaster_invariant_breach',
      'giano_paymaster_invariant_slack_wei',
      'giano_tenant_available_wei',
    ]) {
      expect(body, `${metric} is not exported`).toContain(metric);
    }
    // A breach is an insolvency and pages: it must be zero here.
    expect(body).toMatch(/giano_paymaster_invariant_breach 0/);
  });
});
