import { expect, test, type Page } from '@playwright/test';
import {
  addVirtualAuthenticator,
  expectOutContains,
  openWalletPopup,
  seedCredentials,
  trackResidentCredentials,
  WALLET_URL,
  type VirtualCredential,
} from './helpers';

/**
 * Full two-origin flows: the dApp fixture uses ONLY the thin SDK; the popup page on
 * the wallet origin runs the ceremonies against a CDP virtual authenticator.
 * Requires the e2e stack (deploy/docker-compose.e2e.yml) to be up.
 *
 * The wallet popup is EPHEMERAL: it closes itself once each connect/sign/transaction
 * resolves. Every later dApp action opens a fresh popup, and the wallet silently
 * restores the connected account from its persisted session (no extra passkey prompt
 * beyond the one needed to actually sign). Because CDP virtual authenticators are
 * per-page, the resident passkey minted during connect is captured and re-seeded into
 * each new popup's authenticator (see helpers).
 */

/** Connects a fresh wallet and returns the resident credential(s) to re-seed later popups. */
async function connect(page: Page): Promise<VirtualCredential[]> {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  const { cdp } = await addVirtualAuthenticator(popup);
  const credentials = trackResidentCredentials(cdp);
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');
  return credentials;
}

/** Opens a fresh popup for a signing/transaction action, seeding the connect credential. */
async function openActionPopup(page: Page, trigger: string, credentials: VirtualCredential[]): Promise<Page> {
  const popup = await openWalletPopup(page, trigger);
  const { cdp, authenticatorId } = await addVirtualAuthenticator(popup);
  await seedCredentials(cdp, authenticatorId, credentials);
  return popup;
}

test('create wallet + connect through the popup pins the dApp origin', async ({ page }) => {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);
  await expect(popup.getByText(new URL(page.url()).origin)).toBeVisible();
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');
});

test('session resume answers eth_accounts without a popup', async ({ page }) => {
  await connect(page);

  await page.reload();
  let popupOpened = false;
  page.on('popup', () => (popupOpened = true));
  const accounts = await page.evaluate(() => window.giano.provider.request({ method: 'eth_accounts' }));
  expect(Array.isArray(accounts) && (accounts as string[]).length).toBeTruthy();
  expect(popupOpened).toBe(false);
});

test('send transaction: fresh popup silently restores, consent approve → receipt', async ({ page }) => {
  const credentials = await connect(page);

  const popup = await openActionPopup(page, '#send', credentials);
  await expect(popup.getByText('Review transaction')).toBeVisible();
  await expect(popup.getByText(new URL(page.url()).origin)).toBeVisible();
  await popup.getByRole('button', { name: 'Approve' }).click();

  await expectOutContains(page, 'userOpHash: 0x');
  await expectOutContains(page, 'receipt:success: true');
});

test('reject returns EIP-1193 4001', async ({ page }) => {
  const credentials = await connect(page);

  const popup = await openActionPopup(page, '#send', credentials);
  await expect(popup.getByText('Review transaction')).toBeVisible();
  await popup.getByRole('button', { name: 'Reject' }).click();
  await expectOutContains(page, 'send:error: rpc:4001');
});

test('personal_sign and typed data through consent', async ({ page }) => {
  const credentials = await connect(page);

  const signPopup = await openActionPopup(page, '#sign', credentials);
  await expect(signPopup.getByText('giano e2e')).toBeVisible();
  await signPopup.getByRole('button', { name: 'Sign' }).click();
  await expectOutContains(page, 'signature: len=');

  const typedPopup = await openActionPopup(page, '#sign-typed', credentials);
  await expect(typedPopup.getByText('hello giano')).toBeVisible();
  await typedPopup.getByRole('button', { name: 'Sign' }).click();
  await expectOutContains(page, 'typedSignature: len=');
});

test('hostile-origin message injection is ignored by the popup', async ({ page }) => {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);

  await page.evaluate(() => {
    const w = window.open('', 'giano-wallet');
    w?.postMessage({ giano: 1, id: '01FORGEDMSG000000000000000', type: 'rpc', payload: { method: 'eth_requestAccounts' } }, '*');
  });

  // consent still required — nothing auto-approved
  await expect(popup.getByRole('button', { name: 'Continue with passkey' })).toBeVisible();
});

test('ROR well-known is served on the wallet origin', async ({ request }) => {
  const response = await request.get(`${WALLET_URL}/.well-known/webauthn`);
  expect(response.ok()).toBeTruthy();
  const body = (await response.json()) as { origins: string[] };
  expect(Array.isArray(body.origins)).toBe(true);
});

test('popup-blocked path yields a typed error', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.addInitScript(() => {
    window.open = () => null;
  });
  await page.goto(process.env.DAPP_URL ?? 'http://app.localhost:4400');
  await page.click('#connect');
  await expectOutContains(page, 'connect:error:', 15_000);
  await context.close();
});
