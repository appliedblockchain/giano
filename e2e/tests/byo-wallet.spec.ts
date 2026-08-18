import { expect, test } from '@playwright/test';
import { addVirtualAuthenticator, connectWallet, expectOutContains, openActionPopup, openWalletPopup, TENANTS } from './helpers';

/**
 * Tenant "byo" end-to-end: the SAME shared backend as tenant "stock", but the wallet
 * origin serves a tenant-BUILT UI (e2e/wallet-byo/, framework-free) instead of Giano's
 * wallet-web. Every assertion on the distinct labels ("Unlock with passkey",
 * "Confirm"/"Decline", "Sign it") is proof that a different UI ran the flow — if the
 * stock UI were accidentally served on this origin, this whole file fails.
 */

const tenant = TENANTS.byo;

test('connect through the BYO UI: distinct branding, pinned dApp origin, working ceremony', async ({ page }) => {
  await page.goto(tenant.dappUrl);
  const popup = await openWalletPopup(page, '#connect');
  await addVirtualAuthenticator(popup);

  // this is visibly NOT the stock Giano UI
  await expect(popup.getByTestId('byo-brand')).toHaveText('BYO Wallet');
  await expect(popup.getByText('Giano')).toHaveCount(0);
  // the pinned dApp origin is shown on the consent screen
  await expect(popup.getByTestId('dapp-origin')).toHaveText(new URL(page.url()).origin);

  await popup.getByRole('button', { name: tenant.ui.connect }).click();
  await expectOutContains(page, 'accounts: ["0x');
});

test('session resume answers eth_accounts without a popup', async ({ page }) => {
  await connectWallet(page, tenant);

  await page.reload();
  let popupOpened = false;
  page.on('popup', () => (popupOpened = true));
  const accounts = await page.evaluate(() => window.giano.provider.request({ method: 'eth_accounts' }));
  expect(Array.isArray(accounts) && (accounts as string[]).length).toBeTruthy();
  expect(popupOpened).toBe(false);
});

test('send transaction through the BYO consent screen → receipt', async ({ page }) => {
  const { credentials } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#send', credentials);
  await expect(popup.getByTestId('byo-tx')).toHaveText(tenant.ui.txHeading);
  await expect(popup.getByTestId('dapp-origin')).toHaveText(new URL(page.url()).origin);
  await popup.getByRole('button', { name: tenant.ui.approveTx }).click();

  await expectOutContains(page, 'userOpHash: 0x');
  await expectOutContains(page, 'receipt:success: true');
});

test('decline returns EIP-1193 4001', async ({ page }) => {
  const { credentials } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#send', credentials);
  await expect(popup.getByTestId('byo-tx')).toBeVisible();
  await popup.getByRole('button', { name: tenant.ui.rejectTx }).click();
  await expectOutContains(page, 'send:error: rpc:4001');
});

test('personal_sign through the BYO sign screen', async ({ page }) => {
  const { credentials } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#sign', credentials);
  await expect(popup.getByText('giano e2e')).toBeVisible(); // payload rendered decoded
  await popup.getByRole('button', { name: tenant.ui.sign }).click();
  await expectOutContains(page, 'signature: len=');
});
