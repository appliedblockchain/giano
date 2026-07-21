import { expect, test } from '@playwright/test';
import { addVirtualAuthenticator, expectOutContains, openWalletPopup, WALLET_URL } from './helpers';

/**
 * Full two-origin flows: the dApp fixture uses ONLY the thin SDK; the popup page on
 * the wallet origin runs the ceremonies against a CDP virtual authenticator.
 * Requires the e2e stack (deploy/docker-compose.e2e.yml) to be up.
 */

test('create wallet + connect through the popup', async ({ page }) => {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);

  await expect(popup.getByText(/Connection request from/)).toBeVisible();
  await expect(popup.getByText(new URL(page.url()).origin)).toBeVisible(); // pinned dApp origin on the consent screen
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();

  await expectOutContains(page, 'accounts: ["0x');
});

test('session resume answers eth_accounts without a popup', async ({ page }) => {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');

  // reload: eth_accounts must answer from the cached session with no popup event
  await page.reload();
  let popupOpened = false;
  page.on('popup', () => (popupOpened = true));
  const accounts = await page.evaluate(() => window.giano.provider.request({ method: 'eth_accounts' }));
  expect(Array.isArray(accounts) && (accounts as string[]).length).toBeTruthy();
  expect(popupOpened).toBe(false);
});

test('send transaction: consent approve → receipt', async ({ page }) => {
  await page.goto('/');
  const connectPopup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(connectPopup);
  await connectPopup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');

  const txPopup = await openWalletPopup(page, '#send');
  await addVirtualAuthenticator(txPopup);
  await expect(txPopup.getByText('Review transaction')).toBeVisible();
  await expect(txPopup.getByText(new URL(page.url()).origin)).toBeVisible();
  await txPopup.getByRole('button', { name: 'Approve' }).click();

  await expectOutContains(page, 'userOpHash: 0x');
  await expectOutContains(page, 'receipt:success: true');
});

test('reject returns EIP-1193 4001', async ({ page }) => {
  await page.goto('/');
  const connectPopup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(connectPopup);
  await connectPopup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');

  const txPopup = await openWalletPopup(page, '#send');
  await txPopup.getByRole('button', { name: 'Reject' }).click();
  await expectOutContains(page, 'send:error: rpc:4001');
});

test('personal_sign and typed data through consent', async ({ page }) => {
  await page.goto('/');
  const connectPopup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(connectPopup);
  await connectPopup.getByRole('button', { name: 'Continue with passkey' }).click();
  await expectOutContains(page, 'accounts: ["0x');

  const signPopup = await openWalletPopup(page, '#sign');
  await addVirtualAuthenticator(signPopup);
  await expect(signPopup.getByText('giano e2e')).toBeVisible(); // human-readable message
  await signPopup.getByRole('button', { name: 'Sign' }).click();
  await expectOutContains(page, 'signature: 0x');

  const typedPopup = await openWalletPopup(page, '#sign-typed');
  await addVirtualAuthenticator(typedPopup);
  await expect(typedPopup.getByText('hello giano')).toBeVisible(); // typed-data view
  await typedPopup.getByRole('button', { name: 'Sign' }).click();
  await expectOutContains(page, 'typedSignature: 0x');
});

test('hostile-origin message injection is ignored by the popup', async ({ page }) => {
  await page.goto('/');
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);

  // inject a spoofed approval-free rpc directly into the popup from the dApp page
  // with a *forged* envelope — the host must ignore anything not on the pinned channel
  await page.evaluate(() => {
    const w = window.open('', 'giano-wallet');
    w?.postMessage({ giano: 1, id: '01FORGEDMSG000000000000000', type: 'rpc', payload: { method: 'eth_requestAccounts' } }, '*');
  });

  // the consent screen is still required — nothing auto-approved
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
  // block popups by denying window.open
  const page = await context.newPage();
  await page.addInitScript(() => {
    // simulate a popup blocker
    window.open = () => null;
  });
  await page.goto(process.env.DAPP_URL ?? 'http://app.localtest.me:4400');
  await page.click('#connect');
  await expectOutContains(page, 'connect:error:', 15_000);
  await context.close();
});
