import { expect, test, type Page } from '@playwright/test';
import { addVirtualAuthenticator, expectOutContains, openWalletPopup, WALLET_URL } from './helpers';

/**
 * Full two-origin flows: the dApp fixture uses ONLY the thin SDK; the popup page on
 * the wallet origin runs the ceremonies against a CDP virtual authenticator.
 * Requires the e2e stack (deploy/docker-compose.e2e.yml) to be up.
 *
 * Note: the wallet popup stays open and connected after the first ceremony, so
 * subsequent dApp actions reuse the SAME popup (no new window event) — the helper
 * `connectAndKeepPopup` returns that persistent popup for reuse.
 */

async function connectAndKeepPopup(page: Page): Promise<Page> {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);
  await expect(popup.getByText(/Connection request from/)).toBeVisible();
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');
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
  await connectAndKeepPopup(page);

  await page.reload();
  let popupOpened = false;
  page.on('popup', () => (popupOpened = true));
  const accounts = await page.evaluate(() => window.giano.provider.request({ method: 'eth_accounts' }));
  expect(Array.isArray(accounts) && (accounts as string[]).length).toBeTruthy();
  expect(popupOpened).toBe(false);
});

test('send transaction: consent approve → receipt', async ({ page }) => {
  const popup = await connectAndKeepPopup(page);

  await page.click('#send'); // reuses the connected popup
  await expect(popup.getByText('Review transaction')).toBeVisible();
  await expect(popup.getByText(new URL(page.url()).origin)).toBeVisible();
  await popup.getByRole('button', { name: 'Approve' }).click();

  await expectOutContains(page, 'userOpHash: 0x');
  await expectOutContains(page, 'receipt:success: true');
});

test('reject returns EIP-1193 4001', async ({ page }) => {
  const popup = await connectAndKeepPopup(page);

  await page.click('#send');
  await expect(popup.getByText('Review transaction')).toBeVisible();
  await popup.getByRole('button', { name: 'Reject' }).click();
  await expectOutContains(page, 'send:error: rpc:4001');
});

test('personal_sign and typed data through consent', async ({ page }) => {
  const popup = await connectAndKeepPopup(page);

  await page.click('#sign');
  await expect(popup.getByText('giano e2e')).toBeVisible();
  await popup.getByRole('button', { name: 'Sign' }).click();
  await expectOutContains(page, 'signature: 0x');

  await page.click('#sign-typed');
  await expect(popup.getByText('hello giano')).toBeVisible();
  await popup.getByRole('button', { name: 'Sign' }).click();
  await expectOutContains(page, 'typedSignature: 0x');
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
