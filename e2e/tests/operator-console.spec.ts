import { expect, test } from '@playwright/test';

import { CHAINS } from '../origins.mjs';
import { chooseDeployment, installWallet, openConsole } from './console-wallet';

/**
 * The console's Operator area against the real stack (specs/OPERATOR-ADMIN-SPECS.md §14.2 step 3):
 * an operator signs in with the console's wallet, sees the tenant registry joined to the devnet
 * paymaster's roster, and takes a tenant through create → suspend → delete without leaving the page.
 *
 * The injected wallet is anvil's account 0, bootstrapped as `ops-console` for the e2e environment
 * (services/wallet-api/src/environments.ts) and holding every paymaster role; its personal_sign is
 * answered by the node.
 */

test.describe('operator console', () => {
  test.beforeEach(async ({ page }) => {
    await installWallet(page, { known: [CHAINS.a.chainId] });
    await openConsole(page);
    await chooseDeployment(page, CHAINS.a.chainId);
    await page.getByRole('button', { name: /^Connect wallet$/ }).click();
    await expect(page.getByRole('button', { name: /^Connected/ })).toBeVisible();
    await page.getByRole('button', { name: 'Operator', exact: true }).click();
    await page.getByRole('button', { name: /Sign in with wallet/ }).click();
    await expect(page.getByText('ops-console')).toBeVisible();
  });

  test('the registry shows the fixture tenants joined to the paymaster roster', async ({ page }) => {
    for (const slug of ['stock', 'byo']) {
      const row = page.getByTestId(`tenant-row-${slug}`);
      await expect(row).toContainText('active');
      await expect(row).toContainText('registered · enabled');
    }
  });

  test('a tenant is created, suspended and deleted from the console', async ({ page }) => {
    // a deleted slug is never reusable and this stack's database may outlive a run
    const slug = `console-${Date.now()}`;

    await page.getByRole('button', { name: /Create tenant/ }).click();
    const create = page.getByRole('dialog');
    await create.getByRole('textbox', { name: 'Slug' }).fill(slug);
    await create.getByRole('textbox', { name: 'Wallet origin' }).fill(`http://wallet-${slug}.localhost`);
    await create.getByRole('textbox', { name: 'Display name' }).fill('Console E2E');
    await create.getByRole('button', { name: 'Create tenant' }).click();
    await expect(create.getByText('These are shown once')).toBeVisible();
    await expect(create.getByText(/^gak_/)).toBeVisible();
    await create.getByRole('button', { name: 'Done' }).click();

    const row = page.getByTestId(`tenant-row-${slug}`);
    await expect(row).toContainText('not registered');

    await row.click();
    await page.getByTestId('tenant-actions').getByRole('button', { name: /Suspend/ }).click();
    const suspend = page.getByRole('dialog', { name: `Suspend ${slug}` });
    await suspend.getByRole('textbox', { name: 'Reason' }).fill('console e2e');
    await suspend.getByRole('button', { name: 'Suspend' }).click();
    await expect(suspend.getByText(/is suspended/)).toBeVisible();
    await suspend.getByRole('button', { name: 'Done' }).click();
    await expect(row).toContainText('suspended');

    await page.getByTestId('tenant-actions').getByRole('button', { name: /Delete/ }).click();
    const remove = page.getByRole('dialog', { name: `Delete ${slug}` });
    await expect(remove.getByRole('button', { name: 'Delete permanently' })).toBeDisabled();
    await remove.getByRole('textbox', { name: 'Type the slug to confirm' }).fill(slug);
    await remove.getByRole('button', { name: 'Delete permanently' }).click();
    await expect(page.getByTestId('tenant-history')).toContainText('delete');
    await page.keyboard.press('Escape');

    // gone from the default list, still there with deleted tenants shown
    await expect(row).toHaveCount(0);
    await page.getByText(/Show deleted tenants/).click();
    await expect(page.getByTestId(`tenant-row-${slug}`)).toContainText('deleted');
  });

  test('on-chain follow-ups, edit and keys: register, disable, re-enable, rename, issue and revoke', async ({ page }) => {
    const slug = `onchain-${Date.now()}`;
    await page.getByRole('button', { name: /Create tenant/ }).click();
    const create = page.getByRole('dialog');
    await create.getByRole('textbox', { name: 'Slug' }).fill(slug);
    await create.getByRole('textbox', { name: 'Wallet origin' }).fill(`http://wallet-${slug}.localhost`);
    await create.getByRole('textbox', { name: 'Display name' }).fill('On-chain E2E');
    await create.getByRole('button', { name: 'Create tenant' }).click();
    // ops-console holds TENANT_ADMIN_ROLE on the devnet paymaster, so registering is offered
    await create.getByRole('textbox', { name: 'Withdrawal address' }).fill('0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    await create.getByRole('button', { name: 'Register on-chain' }).click();
    await expect(create.getByText(/Registered on e2e devnet A/)).toBeVisible({ timeout: 30_000 });
    await create.getByRole('button', { name: 'Done' }).click();

    const row = page.getByTestId(`tenant-row-${slug}`);
    await expect(row).toContainText('registered · enabled', { timeout: 30_000 });

    // suspend, and take the offered on-chain disable
    await row.click();
    const actions = page.getByTestId('tenant-actions');
    await actions.getByRole('button', { name: /Suspend/ }).click();
    const suspend = page.getByRole('dialog', { name: `Suspend ${slug}` });
    await suspend.getByRole('textbox', { name: 'Reason' }).fill('on-chain e2e');
    await suspend.getByRole('button', { name: 'Suspend' }).click();
    await suspend.getByRole('button', { name: 'Disable on-chain' }).click();
    await expect(page.getByText(new RegExp(`Disable ${slug} confirmed`))).toBeVisible({ timeout: 30_000 });
    await suspend.getByRole('button', { name: 'Done' }).click();
    await page.keyboard.press('Escape');
    await expect(row).toContainText('registered · disabled', { timeout: 30_000 });

    // resume, and re-enable
    await row.click();
    await actions.getByRole('button', { name: /Resume/ }).click();
    const resume = page.getByRole('dialog', { name: `Resume ${slug}` });
    await resume.getByRole('button', { name: 'Resume' }).click();
    await resume.getByRole('button', { name: 'Enable on-chain' }).click();
    await expect(page.getByText(new RegExp(`Enable ${slug} confirmed`))).toBeVisible({ timeout: 30_000 });
    await resume.getByRole('button', { name: 'Done' }).click();

    // edit: rename
    await actions.getByRole('button', { name: /Edit/ }).click();
    const edit = page.getByRole('dialog', { name: `Edit ${slug}` });
    await edit.getByRole('textbox', { name: 'Display name' }).fill('Renamed in the console');
    await edit.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Renamed in the console').first()).toBeVisible();

    // issue a key, then revoke it
    await actions.getByRole('button', { name: /Issue key/ }).click();
    const issue = page.getByRole('dialog', { name: `Issue an admin key for ${slug}` });
    await issue.getByRole('textbox', { name: 'Label' }).fill('second');
    await issue.getByRole('button', { name: 'Issue key' }).click();
    await expect(issue.getByText(/^gak_/)).toBeVisible();
    await issue.getByRole('button', { name: 'Done' }).click();
    const revokeButtons = page.getByRole('button', { name: 'Revoke' });
    await expect(revokeButtons).toHaveCount(2);
    await revokeButtons.last().click();
    await page.getByRole('dialog', { name: /Revoke admin key/ }).getByRole('button', { name: 'Revoke' }).click();
    await expect(revokeButtons).toHaveCount(1);
    await expect(page.getByTestId('tenant-history')).toContainText('admin-key-revoke');
  });

  test('operators are added and removed from the console, but never yourself', async ({ page }) => {
    // a fresh id and address per run: this stack's database may outlive a run
    const id = `ops-run-${Date.now()}`;
    const address = `0x${Date.now().toString(16).padStart(40, '0')}`;

    await page.getByRole('tab', { name: /Operators/ }).click();
    for (const bootstrapped of ['ops-e2e', 'ops-console', 'giovanni']) {
      await expect(page.getByTestId(`operator-row-${bootstrapped}`)).toBeVisible();
    }
    // the signed-in operator has no Remove button on their own row
    const me = page.getByTestId('operator-row-ops-console');
    await expect(me).toContainText('you');
    await expect(me.getByRole('button', { name: /Remove/ })).toHaveCount(0);

    await page.getByRole('button', { name: /Add operator/ }).click();
    const add = page.getByRole('dialog', { name: 'Add operator' });
    await add.getByRole('textbox', { name: 'Id' }).fill(id);
    await add.getByRole('textbox', { name: 'Wallet address' }).fill(address);
    await add.getByRole('button', { name: 'Add operator' }).click();
    const row = page.getByTestId(`operator-row-${id}`);
    await expect(row).toContainText(address);
    await expect(row).toContainText('ops-console');

    await row.getByRole('button', { name: /Remove/ }).click();
    await page.getByRole('dialog', { name: `Remove ${id}` }).getByRole('button', { name: 'Remove operator' }).click();
    await expect(row).toHaveCount(0);
    await expect(page.getByTestId('operator-history')).toContainText(`remove`);
    await expect(page.getByTestId('operator-history')).toContainText(id);
  });

  test('a reload signs the operator out, and the session was never stored', async ({ page }) => {
    const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }) + document.cookie);
    expect(stored).not.toContain('gos_');
    await page.reload();
    await page.getByRole('button', { name: 'Operator', exact: true }).click();
    await expect(page.getByRole('button', { name: /Sign in with wallet/ })).toBeVisible();
  });
});
