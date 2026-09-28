import { expect, test } from '@playwright/test';
import { CHAINS, ORIGINS } from '../../origins.mjs';
import { addVirtualAuthenticator, openActionPopup, openWalletPopup, TENANTS, trackResidentCredentials } from '../helpers';

/**
 * Smoke coverage of the REFERENCE dApp (services/custom-example) on its own origin, tenant `stock`.
 * Opt-in: `pnpm test:demo` (DEMO=1 selects this project and starts the demo's dev server). The
 * fixture suite is untouched — this file is ignored by the default `chromium` project.
 *
 * What it proves: the page comes up with its preflight verdict, connecting through the header grants
 * an account, a sponsored send produces a `confirmed` ledger row with a receipt, and connecting on
 * chain B grants the SAME address (the identity invariant, R11).
 */
const tenant = TENANTS.stock;

test('preflight, connect, sponsored send, identity across chains', async ({ page }) => {
  await page.goto(ORIGINS.demo);

  // The landing tab is up; the preflight verdict is under the header on every tab.
  await expect(page.getByTestId('home-connect')).toBeVisible();
  await expect(page.getByTestId('preflight-line')).toBeVisible();
  await page.getByTestId('tab-setup').click();
  await expect(page.getByTestId('preflight-wallet')).toHaveAttribute('data-state', 'pass');
  await expect(page.getByTestId('preflight-coop')).toHaveAttribute('data-state', 'pass');

  // Connect on chain A through the header.
  const popup = await openWalletPopup(page, '[data-testid=connect]');
  const { cdp } = await addVirtualAuthenticator(popup);
  const credentials = trackResidentCredentials(cdp);
  await popup.getByRole('button', { name: tenant.ui.connect }).click();
  await expect(page.getByTestId('account')).toBeVisible();
  const shortAddress = (await page.getByTestId('account').textContent()) ?? '';
  expect(shortAddress).toMatch(/^0x[0-9a-fA-F]{4}…[0-9a-fA-F]{4}$/);

  // A sponsored send: eth_sendTransaction → receipt → a confirmed outcome row (and a ledger row) with the paymaster.
  await page.getByTestId('tab-transactions').click();
  const sendPopup = await openActionPopup(page, '[data-testid=send]', credentials);
  await expect(sendPopup.getByText(tenant.ui.txHeading)).toBeVisible();
  await expect(sendPopup.getByTestId('consent-chain')).toHaveText(CHAINS.a.name);
  await sendPopup.getByRole('button', { name: tenant.ui.approveTx }).click();
  const confirmed = page.locator('[data-testid=outcome-row][data-status=confirmed]').first();
  await expect(confirmed).toBeVisible({ timeout: 90_000 });
  await expect(confirmed).toContainText('gas paid by the app');
  await page.getByTestId('tab-ledger').click();
  await expect(page.locator('[data-testid=ledger-row][data-status=confirmed]').first()).toContainText('eth_sendTransaction');

  // Connect on chain B: a second provider, its own handshake — and the SAME address (R11).
  await page.getByTestId('tab-setup').click();
  await page.getByTestId('chain-selector').getByText(CHAINS.b.name).click();
  const connectB = await openActionPopup(page, '[data-testid=connect-chain]', credentials);
  await expect(connectB.getByTestId('consent-chain')).toHaveText(CHAINS.b.name);
  await connectB.getByRole('button', { name: tenant.ui.connect }).click();
  await page.getByTestId('tab-wallet').click();
  await expect(page.getByTestId('identity-held')).toBeVisible();
  await expect(page.locator('[data-testid=violation]')).toHaveCount(0);
});
