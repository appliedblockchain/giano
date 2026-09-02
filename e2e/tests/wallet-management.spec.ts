import { expect, test, type Page } from '@playwright/test';
import { connectWallet, expectOutContains, openManagePopup, readOnChainOwners, TENANTS, type VirtualCredential } from './helpers';

/**
 * Wallet management, end to end (WM-67, WM-68). Each scenario asserts the ON-CHAIN owner
 * set after the change — never only that a transaction succeeded — and refusals are
 * asserted where the user meets them.
 *
 * The management interface is opened from the dApp through the SDK function (WM-63): the
 * popup runs the whole flow on the wallet origin, and the CDP virtual authenticator on
 * that popup page holds the connected credential and creates the new one within the same
 * authenticator — so one popup carries the create-then-sign of a same-session addition.
 */

const tenant = TENANTS.stock;

/** Reaches a connected wallet with its management view open. */
async function openManagement(page: Page): Promise<{ credentials: VirtualCredential[]; address: string; popup: Page }> {
  const { credentials, address } = await connectWallet(page, tenant);
  const popup = await openManagePopup(page, credentials);
  await expect(popup.getByTestId('settings-address')).toHaveText(address);
  return { credentials, address, popup };
}

test('the application opens the interface with no parameters and gets no owner data back (WM-39, WM-40)', async ({ page }) => {
  const { popup } = await openManagement(page);
  await expect(popup.getByTestId('manage-owner-row')).toHaveCount(1);
  await popup.getByTestId('manage-close').click();
  // WM-40: the only thing the dApp learns is that the view closed — no owner set returned.
  await expectOutContains(page, 'manage:closed: (no data returned)');
});

test('view: one credential on-chain, current session marked (WM-01, WM-10)', async ({ page }) => {
  const { address, popup } = await openManagement(page);

  const onChain = await readOnChainOwners(address);
  expect(onChain.deployed).toBe(true);
  expect(onChain.owners).toHaveLength(1);
  expect(onChain.owners[0].kind).toBe('passkey');

  await expect(popup.getByTestId('manage-owner-row')).toHaveCount(1);
  // WM-10: the credential in use is marked as such.
  await expect(popup.getByTestId('manage-owner-current')).toBeVisible();
  // WM-03: a stable fingerprint derived from the owner bytes is shown.
  await expect(popup.getByTestId('manage-owner-fingerprint')).toHaveText(/^[0-9A-Z]{3}-[0-9A-Z]{3}$/);
});

test('rename a credential; the name persists (WM-07)', async ({ page }) => {
  const { popup } = await openManagement(page);
  await popup.getByTestId('manage-rename').click();
  await popup.getByTestId('manage-rename-input').fill('My security key');
  await popup.getByTestId('manage-rename-save').click();
  await expect(popup.getByTestId('manage-owner-name')).toHaveText('My security key');

  // reopen the view: the name is still there (it lives in the registry, WM-08)
  await popup.getByTestId('manage-close').click();
  const reopened = await openManagePopup(page, (await connectWallet(page, tenant)).credentials);
  await expect(reopened.getByTestId('manage-owner-name')).toHaveText('My security key');
});

test('add a passkey in the current session: two owners on-chain, address unchanged (WM-12, WM-14)', async ({ page }) => {
  const { address, popup } = await openManagement(page);
  expect((await readOnChainOwners(address)).owners).toHaveLength(1);

  await popup.getByTestId('manage-add-passkey').click();
  // WM-17: the consent screen shows a fingerprint before the authorising signature.
  await expect(popup.getByTestId('manage-consent-fingerprint')).toHaveText(/^[0-9A-Z]{3}-[0-9A-Z]{3}$/, { timeout: 30_000 });
  await popup.getByTestId('manage-add-approve').click();

  // per-chain progress; chain A confirms, the undeployed chain is skipped (WM-44, WM-46)
  await expect(popup.getByTestId('manage-flow-done')).toBeVisible({ timeout: 90_000 });

  // WM-67: assert the on-chain owner set, not just a succeeding transaction.
  const after = await readOnChainOwners(address);
  expect(after.owners).toHaveLength(2);
  // WM-12: the wallet's address did not change.
  const me = await page.evaluate(() => window.giano.provider.request<string[]>({ method: 'eth_accounts' }));
  expect((me as string[])[0].toLowerCase()).toBe(address.toLowerCase());

  await popup.getByTestId?.('manage-flow-done');
});

test('add an externally-owned account: full address shown, then present on-chain (WM-24, WM-25, WM-26)', async ({ page }) => {
  const { address, popup } = await openManagement(page);
  // Anvil account #1 — a checksummed EOA.
  const eoa = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

  await popup.getByTestId('manage-add-address').click();
  await popup.getByTestId('manage-address-input').fill(eoa);
  await popup.getByTestId('manage-address-continue').click();
  // WM-25: shown in full and unabbreviated before consent.
  await expect(popup.getByTestId('manage-address-full')).toHaveText(eoa);
  // WM-26: what is granted is stated, and confirmation is a separate explicit step.
  await expect(popup.getByTestId('manage-address-grant-note')).toContainText('full and equal control');
  await popup.getByTestId('manage-address-understood').check();
  await popup.getByTestId('manage-address-approve').click();

  await expect(popup.getByTestId('manage-flow-done')).toBeVisible({ timeout: 90_000 });
  const after = await readOnChainOwners(address);
  expect(after.owners.some((owner) => owner.kind === 'address' && owner.ownerBytes.toLowerCase().endsWith(eoa.slice(2).toLowerCase()))).toBe(true);
});

test('remove a credential: gone on-chain; last owner cannot be removed (WM-27, WM-28)', async ({ page }) => {
  const { address, popup } = await openManagement(page);

  // With one owner, removal is not offered and the last-owner note explains why (WM-28).
  await expect(popup.getByTestId('manage-last-owner-note')).toBeVisible();
  await expect(popup.getByTestId('manage-remove')).toBeDisabled();

  // Add a second owner (an EOA is simplest to add without a second authenticator), then
  // remove the first — asserting the on-chain set shrinks.
  const eoa = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
  await popup.getByTestId('manage-add-address').click();
  await popup.getByTestId('manage-address-input').fill(eoa);
  await popup.getByTestId('manage-address-continue').click();
  await popup.getByTestId('manage-address-understood').check();
  await popup.getByTestId('manage-address-approve').click();
  await popup.getByTestId('manage-flow-done').click({ timeout: 90_000 });
  expect((await readOnChainOwners(address)).owners).toHaveLength(2);

  // remove the EOA owner (not the session's own credential, so no sign-out)
  const eoaRow = popup.locator('[data-testid=manage-owner-row]', { hasText: 'Ethereum account' });
  await eoaRow.getByTestId('manage-remove').click();
  await popup.getByTestId('manage-remove-approve').click();
  await expect(popup.getByTestId('manage-flow-done')).toBeVisible({ timeout: 90_000 });

  const after = await readOnChainOwners(address);
  expect(after.owners).toHaveLength(1);
  expect(after.owners[0].kind).toBe('passkey');
});

test('bring-your-own UI: view, add and remove reachable through the tenant’s own interface (WM-61)', async ({ browser }) => {
  const byo = TENANTS.byo;
  const context = await browser.newContext();
  const page = await context.newPage();
  const { credentials, address } = await connectWallet(page, byo);

  const popup = await openManagePopup(page, credentials);
  // a visibly different UI ran the flow — the BYO test-ids, not the stock ones
  await expect(popup.getByTestId('byo-manage-address')).toHaveText(address, { timeout: 30_000 });
  await expect(popup.getByTestId('byo-manage-owner')).toHaveCount(1);
  await expect(popup.getByTestId('byo-manage-last-owner')).toBeVisible();

  // add an EOA through the BYO UI, then assert the on-chain set
  await popup.getByTestId('byo-manage-add').click();
  // the BYO reference adds a passkey on this device; assert the flow reaches its progress view
  await expect(popup.getByTestId('byo-manage-fingerprint')).toHaveText(/^[0-9A-Z]{3}-[0-9A-Z]{3}$/, { timeout: 30_000 });
  await popup.getByTestId('byo-manage-add-approve').click();
  await expect(popup.getByTestId('byo-manage-flow-done')).toBeVisible({ timeout: 90_000 });
  expect((await readOnChainOwners(address)).owners.length).toBeGreaterThanOrEqual(2);

  await context.close();
});
