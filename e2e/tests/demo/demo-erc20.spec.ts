import { expect, test } from '@playwright/test';
import { ORIGINS } from '../../origins.mjs';
import { addVirtualAuthenticator, openActionPopup, openWalletPopup, TENANTS, trackResidentCredentials } from '../helpers';

/**
 * The Tokens tab against Giano's test ERC-20 at its CREATE2 address (R13, R14): load the default token,
 * mint (anyone can), transfer to self, and ask for an EIP-2612 permit — which this token does not
 * support, so the demo must record a clean "no permit" outcome without opening the wallet.
 */
const tenant = TENANTS.stock;
const DEFAULT_TOKEN = '0x9967bDf929856643e92EF65eefdE1fF8250774D8';

test('default token: load, mint, transfer, and the no-permit path', async ({ page }) => {
  await page.goto(ORIGINS.demo);
  const popup = await openWalletPopup(page, '[data-testid=connect]');
  const { cdp } = await addVirtualAuthenticator(popup);
  const credentials = trackResidentCredentials(cdp);
  await popup.getByRole('button', { name: tenant.ui.connect }).click();
  await expect(page.getByTestId('account')).toBeVisible();

  await page.getByTestId('tab-tokens').click();
  // Prefilled with the chain's default token — the same address on every chain.
  await expect(page.getByPlaceholder('0x…').first()).toHaveValue(DEFAULT_TOKEN);
  await page.getByTestId('load-token').click();
  await expect(page.getByText('Private ERC20 · PE2 · 18 decimals')).toBeVisible();

  // Mint 100 PE2 to self, sponsored: confirmed, with the token balance delta on the entry.
  const mintPopup = await openActionPopup(page, '[data-testid=erc20-run]', credentials);
  await expect(mintPopup.getByText(tenant.ui.txHeading)).toBeVisible();
  await mintPopup.getByRole('button', { name: tenant.ui.approveTx }).click();
  const minted = page.locator('[data-testid=outcome-row][data-status=confirmed]').first();
  await expect(minted).toBeVisible({ timeout: 90_000 });
  await expect(minted).toContainText('Mint 100 PE2');
  await expect(minted).toContainText('gas paid by the app');
  await minted.click();
  await expect(minted).toContainText('100000000000000000000'); // 100 PE2 in raw units, after the mint
  await expect(page.getByText(/Balance/).locator('..')).toContainText('100 PE2');

  // Transfer 100 PE2 to self: a plain ERC-20 call, sponsored, confirmed; balance unchanged.
  await page.getByLabel('Action').selectOption('transfer');
  const transferPopup = await openActionPopup(page, '[data-testid=erc20-run]', credentials);
  await transferPopup.getByRole('button', { name: tenant.ui.approveTx }).click();
  const transferred = page.locator('[data-testid=outcome-row][data-status=confirmed]').first();
  await expect(transferred).toContainText('Transfer 100 PE2', { timeout: 90_000 });

  // Permit: the token has no nonces(), so the demo records a clean failure and opens no popup.
  await page.getByLabel('Action').selectOption('permit');
  let popupOpened = false;
  page.on('popup', () => (popupOpened = true));
  await page.getByTestId('erc20-run').click();
  const noPermit = page.locator('[data-testid=outcome-row][data-status=failed]').first();
  await expect(noPermit).toBeVisible();
  await expect(noPermit).toContainText('Sign permit');
  await noPermit.click();
  await expect(noPermit).toContainText('does not implement EIP-2612');
  expect(popupOpened).toBe(false);
});
