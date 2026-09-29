/**
 * What the user is shown when asked to approve a transaction (openspec change
 * transaction-display-mappings, spec `wallet-transaction-review`).
 *
 * Three paths, each asserted where the user meets it:
 *   - a call the tenant has described (the demo ERC-20; both tenants' mappings are published at
 *     bring-up by e2e/devnet/provision-tx-mappings.mjs, through the real admin API): an intent
 *     sentence, no raw calldata — in the stock wallet and in the bring-your-own wallet's own rendering;
 *   - a plain value transfer, described in the chain's currency with no mapping at all;
 *   - a call nothing describes (malformed selector-only calldata): the "cannot explain" warning
 *     and the raw data, and nothing that looks like a description.
 * The generic (selector-only) fallback has no dApp fixture that reaches it — every contract the
 * fixture calls is either mapped or unmapped-and-malformed — so it is covered by the library's and
 * the kit's unit tests instead.
 */

import { expect, test } from '@playwright/test';
import { connectWallet, openActionPopup, TENANTS } from './helpers';

test('stock wallet: a described transfer leads with the intent and shows no raw calldata', async ({ page }) => {
  const tenant = TENANTS.stock;
  const { credentials, address } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#send-erc20', credentials);
  await expect(popup.getByText(tenant.ui.txHeading)).toBeVisible();

  const intent = popup.getByTestId('tx-intent');
  await expect(intent).toBeVisible();
  await expect(intent).toHaveAttribute('data-source', 'mapping');
  // "Send 0 <symbol> to 0x1234…abcd": the demo transfer is to self, for nothing.
  await expect(intent).toContainText(/^Send 0 /);
  await expect(intent).toContainText(`${address.slice(0, 6)}…${address.slice(-4)}`);
  const recipient = popup.getByTestId('tx-field').filter({ hasText: 'Recipient' });
  await expect(recipient).toBeVisible();
  // Short by default, full on demand: the whole checksummed address is one click away.
  const toggle = recipient.getByTestId('tx-address');
  await expect(toggle).toHaveText(`${address.slice(0, 6)}…${address.slice(-4)}`);
  await toggle.click();
  await expect(toggle).toHaveText(new RegExp(`^${address}$`, 'i'));
  await toggle.click();
  await expect(toggle).toHaveAttribute('data-expanded', 'false');

  await expect(popup.getByTestId('tx-raw')).toHaveCount(0);
  await expect(popup.getByTestId('tx-unknown')).toHaveCount(0);
  await expect(popup.getByTestId('tx-generic-note')).toHaveCount(0);

  // The approve control exists only once the summary is on screen (and the pre-flight passed).
  await expect(popup.getByRole('button', { name: tenant.ui.approveTx })).toBeVisible();
});

test('stock wallet: a plain value transfer is described in the chain currency without any mapping', async ({ page }) => {
  const tenant = TENANTS.stock;
  const { credentials } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#send', credentials);
  const intent = popup.getByTestId('tx-intent');
  await expect(intent).toHaveAttribute('data-source', 'native');
  await expect(intent).toContainText(/^Send 0 ETH to 0x/);
  await expect(popup.getByTestId('tx-raw')).toHaveCount(0);
});

test('stock wallet: an unexplainable call shows the warning and the raw data, and nothing invented', async ({ page }) => {
  const tenant = TENANTS.stock;
  const { credentials } = await connectWallet(page, tenant);

  // `#send-unlisted` sends a bare selector with no arguments: a call no mapping can decode.
  const popup = await openActionPopup(page, '#send-unlisted', credentials);
  await expect(popup.getByText(tenant.ui.txHeading)).toBeVisible();

  const unknown = popup.getByTestId('tx-unknown');
  await expect(unknown).toBeVisible();
  await expect(unknown).toHaveAttribute('data-reason', 'decode-failed');
  await expect(unknown).toContainText('cannot explain this transaction');
  await expect(unknown).toContainText('0xa9059cbb');
  await expect(popup.getByTestId('tx-raw')).toHaveText('0xa9059cbb');
  await expect(popup.getByTestId('tx-intent')).toHaveCount(0);
  await expect(popup.getByTestId('tx-field')).toHaveCount(0);

  // The sponsorship rules refuse this contract, so the only way out is Close — that path is
  // covered by the sponsorship suite; here it is enough that the screen settled.
  await popup.getByRole('button', { name: /Close|Reject/ }).click();
});

test('BYO wallet: the same transfer is described from its tenant\'s mapping, in its own rendering', async ({ page }) => {
  const tenant = TENANTS.byo;
  const { credentials, address } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#send-erc20', credentials);
  await expect(popup.getByTestId('byo-tx')).toHaveText(tenant.ui.txHeading);

  const intent = popup.getByTestId('byo-tx-intent');
  await expect(intent).toBeVisible();
  // Tenant "byo" publishes the same mapping as "stock" at bring-up: the same kit call, a different UI.
  await expect(intent).toHaveAttribute('data-source', 'mapping');
  await expect(intent).toContainText(/^Send 0 /);
  await expect(intent).toContainText(`${address.slice(0, 6)}…${address.slice(-4)}`);
  // The BYO rendering shows the recipient in full.
  await expect(popup.getByText(new RegExp(`Recipient: ${address}`, 'i'))).toBeVisible();
  await expect(popup.getByTestId('byo-tx-generic')).toHaveCount(0);
  await expect(popup.getByTestId('byo-tx-raw')).toHaveCount(0);
  await expect(popup.getByRole('button', { name: tenant.ui.approveTx })).toBeVisible();
});
