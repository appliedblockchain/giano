import { expect, test, type Page } from '@playwright/test';
import { CHAINS, ORIGINS } from '../../origins.mjs';
import { addVirtualAuthenticator, openActionPopup, openWalletPopup, TENANTS, trackResidentCredentials, type VirtualCredential } from '../helpers';

test.use({ actionTimeout: 15_000 });
const tenant = TENANTS.stock;
const latest = (page: Page, section: string) => page.locator(`#${section} [data-testid=outcome-row]`).first();

async function connect(page: Page): Promise<VirtualCredential[]> {
  await page.goto(ORIGINS.demo);
  const popup = await openWalletPopup(page, '[data-testid=connect]');
  const { cdp } = await addVirtualAuthenticator(popup);
  const credentials = trackResidentCredentials(cdp);
  await popup.getByRole('button', { name: tenant.ui.connect }).click();
  await expect(page.getByTestId('account')).toBeVisible({ timeout: 20_000 });
  return credentials;
}

async function approve(page: Page, trigger: string, credentials: VirtualCredential[], button = 'Approve') {
  const popup = await openActionPopup(page, trigger, credentials);
  await popup.getByRole('button', { name: button, exact: true }).click();
}

// Every transaction is submitted to the safe-mode bundler, and checked via its receipt.
for (const chain of [CHAINS.a, CHAINS.b]) {
  test(`${chain.name}: sends, token calls, signatures, raw pipeline and authenticated read`, async ({ page }) => {
    test.setTimeout(360_000);
    const credentials = await connect(page);
    if (chain.chainId === CHAINS.b.chainId) {
      await page.getByTestId('tab-setup').click();
      await page.getByTestId('chain-selector').getByText(chain.name).click();
      await approve(page, '[data-testid=connect-chain]', credentials, tenant.ui.connect);
      await page.getByTestId('tab-wallet').click();
      await expect(page.getByTestId('identity-held')).toBeVisible({ timeout: 20_000 });
    }

    await page.getByTestId('tab-transactions').click();
    await approve(page, '[data-testid=send]', credentials);
    await expect(latest(page, 'transactions')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
    await expect(latest(page, 'transactions')).toContainText('gas paid by the app');

    // The payer selector declares an expectation; the wallet decides sponsorship.
    await page.getByTestId('payer').getByText('Paid by this account').click();
    await approve(page, '[data-testid=send]', credentials);
    await expect(latest(page, 'transactions')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
    await expect(latest(page, 'transactions')).toContainText('payer differs from declaration');
    await page.getByTestId('payer').getByText('Sponsored by the app').click();
    await page.getByRole('button', { name: 'Fund from devnet', exact: true }).click();
    await expect(latest(page, 'transactions')).toHaveAttribute('data-status', 'ok');
    await page.locator('#transactions').getByLabel('Action', { exact: true }).selectOption('value');
    await page.getByLabel('Value (ETH)', { exact: true }).fill('0.001');
    await approve(page, '[data-testid=send]', credentials);
    await expect(latest(page, 'transactions')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
    await page.locator('#transactions').getByLabel('Action', { exact: true }).selectOption('custom');
    await page.getByLabel('Value (ETH)', { exact: true }).fill('0');
    await page.getByLabel('To', { exact: true }).fill('0x9967bDf929856643e92EF65eefdE1fF8250774D8');
    await page.getByLabel('Calldata (hex)', { exact: true }).fill('0xa0712d68' + '0'.repeat(63) + '1');
    await approve(page, '[data-testid=send]', credentials);
    await expect(latest(page, 'transactions')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });

    for (const method of ['personal_sign', 'eth_sign', 'eth_signTypedData_v4']) {
      await page.locator('#signing').getByLabel('Method', { exact: true }).selectOption(method);
      await approve(page, '[data-testid=sign]', credentials, 'Sign');
      await expect(latest(page, 'signing')).toHaveAttribute('data-status', 'ok');
    }

    await page.getByTestId('tab-tokens').click();
    await page.getByTestId('load-token').click();
    await expect(page.getByText('Private ERC20 · PE2 · 18 decimals')).toBeVisible();
    for (const action of ['mint', 'transfer', 'approve']) {
      await page.locator('#erc20').getByLabel('Action', { exact: true }).selectOption(action);
      await approve(page, '[data-testid=erc20-run]', credentials);
      await expect(latest(page, 'erc20')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
    }
    await expect(page.getByText('Allowance', { exact: true }).locator('..')).toContainText('100 PE2');
    await page.locator('#erc20').getByLabel('Action', { exact: true }).selectOption('permit');
    await page.getByTestId('erc20-run').click();
    await expect(latest(page, 'erc20')).toHaveAttribute('data-status', 'failed');
    await latest(page, 'erc20').click();
    await expect(latest(page, 'erc20')).toContainText('does not implement EIP-2612');

    await page.getByTestId('tab-advanced').click();
    await openWalletPopup(page, '#raw-userop button:has-text("1 · Prepare")');
    await expect(latest(page, 'raw-userop')).toHaveAttribute('data-status', 'ok');
    await approve(page, '#raw-userop button:has-text("2 · Sign")', credentials, 'Sign');
    await expect(latest(page, 'raw-userop')).toHaveAttribute('data-status', 'ok');
    await openWalletPopup(page, '#raw-userop button:has-text("3 · Send")');
    await expect(latest(page, 'raw-userop')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
    await approve(page, '#raw-userop button:has-text("Call privateBalanceOf")', credentials, 'Sign');
    await expect(latest(page, 'raw-userop')).toHaveAttribute('data-status', 'ok');
    await approve(page, '#raw-userop button:has-text("Call without to/data")', credentials, 'Sign');
    await expect(latest(page, 'raw-userop')).toHaveAttribute('data-status', 'refused');

    await page.getByTestId('tab-wallet').click();
    const management = await openActionPopup(page, '[data-testid=manage]', credentials);
    await expect(management.getByTestId('manage-owner-row')).toHaveCount(1);
    await management.getByTestId('manage-close').click();
    await expect(latest(page, 'management')).toHaveAttribute('data-status', 'ok');
    await page.getByTestId('tab-ledger').click();
    await expect(page.locator('[data-testid=violation]')).toHaveCount(0);
    await expect(page.locator('[data-testid=ledger-row][data-status=confirmed]')).toHaveCount(8);
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGINS.demo });
    await page.getByTestId('ledger-export').click();
    const exported = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
    expect(exported.entries.filter((entry: { status: string }) => entry.status === 'confirmed')).toHaveLength(8);
    expect(exported.dappOrigin).toBe(ORIGINS.demo);
    await page.locator('#ledger').getByRole('button', { name: 'Clear', exact: true }).click();
    await expect(page.getByTestId('ledger-row')).toHaveCount(0);
  });
}

test('chain controls, failure lab, revoke and reconnect', async ({ page }) => {
  test.setTimeout(240_000);
  const credentials = await connect(page);
  await page.getByTestId('tab-setup').click();
  await page.getByRole('button', { name: 'Developer controls', exact: true }).click();
  await page.getByRole('button', { name: 'Read eth_chainId', exact: true }).click();
  await expect(latest(page, 'chain')).toHaveAttribute('data-status', 'ok');
  for (const method of ['switchEthereumChain', 'addEthereumChain']) {
    await page.getByRole('button', { name: `Try ${method}`, exact: true }).click();
    await expect(latest(page, 'chain')).toHaveAttribute('data-status', 'refused');
    await latest(page, 'chain').click();
    await expect(latest(page, 'chain')).toContainText('4200');
  }
  await page.getByTestId('tab-failure-lab').click();
  const nativeOpen = await page.evaluateHandle(() => window.open);
  await page.evaluate(() => { window.open = () => null; });
  await page.getByTestId('lab-popup').click();
  await expect(latest(page, 'failure-lab')).toHaveAttribute('data-status', 'refused');
  await latest(page, 'failure-lab').click();
  await expect(latest(page, 'failure-lab')).toContainText('POPUP_BLOCKED');
  await page.evaluate((open) => { window.open = open; }, nativeOpen);
  await nativeOpen.dispose();
  for (const [control, message] of [['unserved', '4902'], ['origin', 'origin-not-allowed']]) {
    await page.getByTestId(`lab-${control}`).click();
    await expect(latest(page, 'failure-lab')).toHaveAttribute('data-status', 'refused');
    await latest(page, 'failure-lab').click();
    await expect(latest(page, 'failure-lab')).toContainText(message);
  }
  for (const control of ['reject', 'unlisted', 'addr', 'hex']) {
    const popup = await openActionPopup(page, `[data-testid=lab-${control}]`, credentials);
    if (control === 'reject') await popup.getByRole('button', { name: 'Reject', exact: true }).click();
    else {
      // Validation/allowlist refusal happens in the wallet before approval.
      await expect(popup.getByTestId('sponsorship-refusal')).toBeVisible();
      await popup.close();
    }
    await expect(latest(page, 'failure-lab')).toHaveAttribute('data-status', 'refused');
  }
  await approve(page, '[data-testid=lab-selfpaid]', credentials);
  await expect(latest(page, 'failure-lab')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
  await expect(latest(page, 'failure-lab')).toContainText('payer differs from declaration');
  await page.getByTestId('lab-revoke').click();
  await expect(page.getByTestId('account')).toHaveCount(0);
  await page.getByTestId('tab-ledger').click();
  await expect(page.getByTestId('ledger-row').filter({ hasText: 'Revoke permissions, then read eth_accounts' })).toHaveAttribute('data-status', 'ok');
  await approve(page, '[data-testid=connect]', credentials, tenant.ui.connect);
  await expect(page.getByTestId('account')).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(page.getByTestId('account')).toHaveCount(0);
});

test('wagmi and RainbowKit adapters connect, send, refuse chain switching and disconnect', async ({ page }) => {
  test.setTimeout(180_000);
  const credentials = await connect(page);
  await page.getByTestId('tab-advanced').click();
  await approve(page, '#adapters button:has-text("Connect via wagmi")', credentials, tenant.ui.connect);
  await expect(page.locator('#adapters')).toContainText('wagmi connected');
  await approve(page, '#adapters button:has-text("Send + waitForUserOperationReceipt")', credentials);
  await expect(latest(page, 'adapters')).toHaveAttribute('data-status', 'confirmed', { timeout: 90_000 });
  await page.locator('#adapters').getByRole('button', { name: 'switchChain → Devnet B', exact: true }).click();
  await expect(latest(page, 'adapters')).toHaveAttribute('data-status', 'refused');
  await page.locator('#adapters').getByRole('button', { name: 'Disconnect wagmi', exact: true }).click();
  await expect(page.locator('#adapters')).toContainText('wagmi disconnected');
  await page.getByRole('button', { name: 'Open RainbowKit connect modal', exact: true }).click();
  await approve(page, '[role=dialog] button:has-text("Giano")', credentials, tenant.ui.connect);
  await expect(page.locator('#adapters')).toContainText('wagmi connected');
  await expect(page.locator('[data-testid=violation]')).toHaveCount(0);
  await page.locator('#adapters').getByRole('button', { name: 'Disconnect wagmi', exact: true }).click();
  await expect(page.locator('#adapters')).toContainText('wagmi disconnected');
});
