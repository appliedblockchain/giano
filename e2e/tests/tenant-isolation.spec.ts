import { expect, test, type BrowserContext } from '@playwright/test';
import {
  addVirtualAuthenticator,
  connectWallet,
  expectOutContains,
  getCredentials,
  openActionPopup,
  openWalletPopup,
  readConnectedAddress,
  seedCredentials,
  TENANTS,
  trackResidentCredentials,
  type VirtualCredential,
} from './helpers';

/**
 * Browser-level tenant-isolation proofs (docs/MULTI-TENANCY-GAPS.md §10). The wallet-api
 * vitest suite owns the API-level negative matrix; this file proves what only a real
 * browser can:
 *  - V8:  passkeys are RP-bound — the assumption most severity downgrades rest on
 *  - V1:  a forced externalUserId collision still yields two wallets
 *  - V5:  a session is rejected across tenant origins THROUGH the real proxies
 *  - V7:  /.well-known/webauthn is Host-scoped through both proxy paths
 *  - V12: full flows on both tenants against one backend in one run (closes G11.3)
 *
 * Each tenant gets its own browser context: storage is cleanly partitioned and the
 * hardcoded popup window name 'giano-wallet' cannot collide across tenants.
 */

test.describe('tenant isolation', () => {
  let contextA: BrowserContext;
  let contextB: BrowserContext;

  test.beforeEach(async ({ browser }) => {
    contextA = await browser.newContext();
    contextB = await browser.newContext();
  });
  test.afterEach(async () => {
    await contextA.close();
    await contextB.close();
  });

  test('V8: the same authenticator yields distinct credentials and wallets per RP ID', async () => {
    // connect on tenant A (stock UI) and capture the resident credential
    const pageA = await contextA.newPage();
    const { credentials: credsA, address: addrA } = await connectWallet(pageA, TENANTS.stock);
    expect(credsA.length).toBeGreaterThan(0);
    expect((credsA[0] as { rpId?: string }).rpId).toBe('wallet.localhost');

    // on tenant B, simulate the SAME device: a fresh virtual authenticator PRE-SEEDED
    // with tenant A's credential
    const pageB = await contextB.newPage();
    await pageB.goto(TENANTS.byo.dappUrl);
    const popup = await openWalletPopup(pageB, '#connect');
    const { cdp, authenticatorId } = await addVirtualAuthenticator(popup);
    await seedCredentials(cdp, authenticatorId, credsA);
    const credsB = trackResidentCredentials(cdp);

    // belt-and-braces: the foreign credential IS stored on this authenticator, so any
    // non-use below is the browser's RP filter, not a failed seed
    const stored = await getCredentials(cdp, authenticatorId);
    expect(stored.length).toBe(1);

    await popup.getByRole('button', { name: TENANTS.byo.ui.connect }).click();
    await expectOutContains(pageB, 'accounts: ["0x');
    const addrB = await readConnectedAddress(pageB);

    // the browser refused to surface the wallet.localhost credential for RP
    // wallet-byo.localhost and minted a NEW one — RP binding is real, not assumed
    expect(credsB.length).toBeGreaterThan(0);
    expect((credsB[0] as { rpId?: string }).rpId).toBe('wallet-byo.localhost');
    expect(credsB[0].credentialId).not.toBe(credsA[0].credentialId);
    expect(addrB.toLowerCase()).not.toBe(addrA.toLowerCase());
  });

  test('V1: a forced externalUserId collision across tenants still yields two wallets', async () => {
    // externalUserId is minted per-origin in localStorage; force the collision the way
    // two independent client apps would ("user-1" everywhere)
    const forceSharedId = () => {
      if (['wallet.localhost', 'wallet-byo.localhost'].includes(location.hostname)) {
        localStorage.setItem('giano:external-user-id', 'shared-e2e-user-1');
      }
    };
    await contextA.addInitScript(forceSharedId);
    await contextB.addInitScript(forceSharedId);

    const pageA = await contextA.newPage();
    const { address: addrA } = await connectWallet(pageA, TENANTS.stock);

    const pageB = await contextB.newPage();
    const { address: addrB } = await connectWallet(pageB, TENANTS.byo);

    // pre-fix C1, the second registration silently merged into the first user and both
    // credentials co-owned ONE wallet — distinct addresses are the observable negative
    expect(addrB.toLowerCase()).not.toBe(addrA.toLowerCase());
  });

  test("V5: tenant A's session token is rejected on tenant B's origin through the real proxies", async ({ request }) => {
    const pageA = await contextA.newPage();
    await connectWallet(pageA, TENANTS.stock);

    // read the session token from the wallet origin's localStorage
    const walletPage = await contextA.newPage();
    await walletPage.goto(TENANTS.stock.walletUrl);
    const token = await walletPage.evaluate(() => localStorage.getItem('giano:session-token'));
    expect(token).toBeTruthy();

    // legitimate: token + its own tenant's Origin, through tenant A's nginx proxy
    const onA = await request.get(`${TENANTS.stock.walletUrl}/api/v1/me`, {
      headers: { authorization: `Bearer ${token}`, origin: TENANTS.stock.walletUrl },
    });
    expect(onA.status()).toBe(200);

    // cross-tenant: same token presented with tenant B's Origin, through the BYO proxy
    const onB = await request.get(`${TENANTS.byo.walletUrl}/api/v1/me`, {
      headers: { authorization: `Bearer ${token}`, origin: TENANTS.byo.walletUrl },
    });
    expect(onB.status()).toBe(401);
  });

  test('V7: /.well-known/webauthn is Host-scoped — each tenant sees only its own origins', async ({ request }) => {
    const seed = async (tenant: typeof TENANTS.stock, origin: string) => {
      const res = await request.post(`${tenant.walletUrl}/api/v1/admin/ror-origins`, {
        headers: { authorization: `Bearer ${tenant.adminKey}` },
        data: { origin },
      });
      expect(res.status()).toBe(201);
    };
    await seed(TENANTS.stock, 'https://ror-stock.example.com');
    await seed(TENANTS.byo, 'https://ror-byo.example.com');

    const onStock = (await (await request.get(`${TENANTS.stock.walletUrl}/.well-known/webauthn`)).json()) as { origins: string[] };
    expect(onStock.origins).toContain('https://ror-stock.example.com');
    expect(onStock.origins).not.toContain('https://ror-byo.example.com');

    const onByo = (await (await request.get(`${TENANTS.byo.walletUrl}/.well-known/webauthn`)).json()) as { origins: string[] };
    expect(onByo.origins).toContain('https://ror-byo.example.com');
    expect(onByo.origins).not.toContain('https://ror-stock.example.com');
  });

  test('V12: full flows on both tenants against one backend, isolated end to end', async () => {
    // tenant A: connect + sponsored tx through the stock UI
    const pageA = await contextA.newPage();
    const a = await connectWallet(pageA, TENANTS.stock);
    const popupA = await openActionPopup(pageA, '#send', a.credentials);
    await popupA.getByRole('button', { name: TENANTS.stock.ui.approveTx }).click();
    await expectOutContains(pageA, 'receipt:success: true');

    // tenant B: connect + sponsored tx through the BYO UI
    const pageB = await contextB.newPage();
    const b = await connectWallet(pageB, TENANTS.byo);
    const popupB = await openActionPopup(pageB, '#send', b.credentials);
    await popupB.getByRole('button', { name: TENANTS.byo.ui.approveTx }).click();
    await expectOutContains(pageB, 'receipt:success: true');

    expect(a.address.toLowerCase()).not.toBe(b.address.toLowerCase());
  });
});
