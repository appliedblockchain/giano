import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { ORIGINS } from '../origins.mjs';
import { connectWallet, openActionPopup, TENANTS } from './helpers';

/**
 * What the user is shown when asked to approve a transaction (openspec change
 * transaction-display-mappings, spec `wallet-transaction-review`).
 *
 * Three paths, each asserted where the user meets it:
 *   - a call the tenant has described (stock wallet, tenant mapping published here in setup):
 *     an intent sentence, no raw calldata;
 *   - a call nothing describes (stock wallet, malformed selector-only calldata): the "cannot
 *     explain" warning and the raw data, and nothing that looks like a description;
 *   - the same demo transfer through the bring-your-own wallet, whose tenant has published
 *     nothing: the kit's generic description, in the BYO UI's own rendering.
 */

const devnetDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'devnet');
const ADDRESSES = JSON.parse(fs.readFileSync(path.join(devnetDir, 'addresses.json'), 'utf8')) as { testErc20: string };

const WALLET_API = process.env.WALLET_API_URL ?? ORIGINS.api;
const CHAIN_A = Number(process.env.CHAIN_ID ?? 31337);

/** An ERC-7730 descriptor for the demo ERC-20, as a tenant would publish it (design D10). */
function demoTokenMapping(chainId: number, address: string) {
  return {
    $schema: 'https://eips.ethereum.org/assets/eip-7730/erc7730-v1.schema.json',
    context: {
      contract: {
        deployments: [{ chainId, address }],
        abi: [
          {
            type: 'function',
            name: 'transfer',
            stateMutability: 'nonpayable',
            inputs: [
              { name: 'to', type: 'address' },
              { name: 'value', type: 'uint256' },
            ],
            outputs: [{ name: '', type: 'bool' }],
          },
        ],
      },
    },
    metadata: { owner: 'Giano E2E', contractName: 'Demo Token' },
    display: {
      formats: {
        'transfer(address to, uint256 value)': {
          intent: 'Send demo tokens',
          interpolatedIntent: 'Send {value} to {to}',
          fields: [
            { path: 'value', label: 'Amount', format: 'tokenAmount', params: { tokenPath: '@.to' } },
            { path: 'to', label: 'Recipient', format: 'addressName' },
          ],
        },
      },
    },
  };
}

test.beforeAll(async () => {
  // Published the way a tenant publishes it: through the admin API with the tenant's own key.
  // Idempotent (full replace), so re-runs against a warm stack are fine.
  const response = await fetch(`${WALLET_API}/v1/admin/tx-mappings/${ADDRESSES.testErc20}?chainId=${CHAIN_A}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${TENANTS.stock.adminKey}` },
    body: JSON.stringify(demoTokenMapping(CHAIN_A, ADDRESSES.testErc20)),
  });
  expect(response.ok, `mapping publish failed: ${response.status} ${await response.text()}`).toBe(true);
});

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
  await expect(popup.getByTestId('tx-field').filter({ hasText: 'Recipient' })).toBeVisible();

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

test('BYO wallet: the same transfer is described generically, in its own rendering', async ({ page }) => {
  const tenant = TENANTS.byo;
  const { credentials } = await connectWallet(page, tenant);

  const popup = await openActionPopup(page, '#send-erc20', credentials);
  await expect(popup.getByTestId('byo-tx')).toHaveText(tenant.ui.txHeading);

  const intent = popup.getByTestId('byo-tx-intent');
  await expect(intent).toBeVisible();
  await expect(intent).not.toBeEmpty();
  // Tenant "byo" has published no mapping, so this is the kit's built-in ERC-20 description.
  await expect(intent).toHaveAttribute('data-source', 'generic');
  await expect(popup.getByTestId('byo-tx-generic')).toBeVisible();
  await expect(popup.getByTestId('byo-tx-raw')).toHaveCount(0);
  await expect(popup.getByRole('button', { name: tenant.ui.approveTx })).toBeVisible();
});
