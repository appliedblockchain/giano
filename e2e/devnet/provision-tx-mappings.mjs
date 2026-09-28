/**
 * Installs the demo tenants' ERC-7730 transaction-display mappings through the real admin API.
 *
 * Same reasoning as provision-sponsorship.mjs, and deliberately the same shape: mappings are a
 * tenant's own to publish, so they go in the way a tenant would put them in — a `PUT` to
 * `/v1/admin/tx-mappings/<contract>` with the tenant's own admin key. Nothing is seeded into the
 * database behind the API, so there is no dev-only path that would have to be disabled in
 * production, and "a tenant that has published no mapping gets raw calldata" stays true here.
 *
 * Why it exists at all: without it the demo's ERC-20 sends render as unreadable calldata in the
 * review screen, which looks like the feature is broken rather than unconfigured. The mapping
 * lives in Postgres, so a `down -v` wipes it — running this at bring-up is what makes the demo
 * show descriptions for everyone who starts the stack, not only for whoever published one by hand.
 *
 * Both tenants, both chains: `demo.localhost` is tenant `stock` and `demo-byo.localhost` is
 * tenant `byo`, they offer the same token on both chains, and mappings are per
 * (tenant, chain, contract) and never inherited — so each pair gets its own explicit PUT.
 *
 * Fails loudly, for the same reason the sponsorship provisioner does: a mapping the API stored but
 * cannot parse yields no description at all, and that is precisely the silent failure this step
 * exists to catch.
 *
 * Usage:  WALLET_API_URL=http://api.localhost node e2e/devnet/provision-tx-mappings.mjs
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
// Compose sets WALLET_API_URL to the container address; the default is for host-side runs,
// where the wallet-api answers to the name portless publishes (see e2e/origins.mjs).
const apiUrl = (process.env.WALLET_API_URL ?? 'http://api.localhost').replace(/\/$/, '');
const addresses = JSON.parse(fs.readFileSync(path.join(dir, 'addresses.json'), 'utf8'));

/** The chains the stack runs, kept in step with provision-sponsorship.mjs. */
const CHAIN_IDS = (process.env.SPONSOR_CHAIN_IDS ?? '31337,31338').split(',').map((id) => Number(id.trim()));

/** Admin keys as `TENANTS_SEED` provisions them in deploy/docker-compose.e2e.yml. */
const TENANT_ADMIN_KEYS = {
  stock: process.env.STOCK_ADMIN_KEY ?? 'e2e-admin-key-stock',
  byo: process.env.BYO_ADMIN_KEY ?? 'e2e-admin-key-byo00',
};

/**
 * The demo ERC-20's descriptor.
 *
 * The address comes from addresses.json rather than being written out here, because it is the
 * same devnet artefact the demo itself is pointed at — a mapping bound to a stale address is
 * indistinguishable, in the UI, from no mapping at all.
 *
 * `deployments` lists every chain, and the API additionally requires the (chainId, address) it is
 * being PUT under to appear there, so one descriptor serves every chain's PUT.
 *
 * Only the two functions the demo actually calls are described. An ABI entry the descriptor does
 * not format is not an error, but an unformatted entry buys nothing either, and a short descriptor
 * is the honest illustration of what a tenant has to write.
 */
function demoTokenMapping(address) {
  const amount = (pathName, label) => ({ path: pathName, label, format: 'tokenAmount', params: { tokenPath: '@.to' } });

  return {
    $schema: 'https://eips.ethereum.org/assets/eip-7730/erc7730-v1.schema.json',
    context: {
      contract: {
        deployments: CHAIN_IDS.map((chainId) => ({ chainId, address })),
        // Inline, not a URL: the wallet resolves a description with no network call of its own.
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
          {
            type: 'function',
            name: 'approve',
            stateMutability: 'nonpayable',
            inputs: [
              { name: 'spender', type: 'address' },
              { name: 'value', type: 'uint256' },
            ],
            outputs: [{ name: '', type: 'bool' }],
          },
        ],
      },
    },
    metadata: { owner: 'Giano demo', contractName: 'Private ERC20' },
    display: {
      formats: {
        // `tokenPath: '@.to'` is the ERC-20 idiom: the token whose decimals and symbol scale the
        // amount is the contract being called, so the wallet resolves it from the call target.
        'transfer(address to, uint256 value)': {
          intent: 'Send demo tokens',
          interpolatedIntent: 'Send {value} to {to}',
          fields: [amount('value', 'Amount'), { path: 'to', label: 'Recipient', format: 'addressName' }],
        },
        'approve(address spender, uint256 value)': {
          intent: 'Approve demo token spending',
          interpolatedIntent: 'Let {spender} spend {value}',
          fields: [amount('value', 'Allowance'), { path: 'spender', label: 'Spender', format: 'addressName' }],
        },
      },
    },
  };
}

async function waitForReady(attempts = 120) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(`${apiUrl}/readyz`);
      if (response.ok) return await response.json();
    } catch (error) {
      if (i === attempts - 1) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`${apiUrl}/readyz never became ready`);
}

await waitForReady();

const contract = addresses.testErc20;
if (!contract) throw new Error('addresses.json carries no testErc20 — regenerate it with `pnpm -F @appliedblockchain/giano-e2e devnet:generate`');

const descriptor = demoTokenMapping(contract);
let failures = 0;

for (const chainId of CHAIN_IDS) {
  for (const tenant of addresses.tenants) {
    const adminKey = TENANT_ADMIN_KEYS[tenant.slug];
    if (!adminKey) {
      console.error(`  ✗ ${tenant.slug}: no admin key known for this tenant`);
      failures += 1;
      continue;
    }

    const url = `${apiUrl}/v1/admin/tx-mappings/${contract}?chainId=${chainId}`;
    const write = await fetch(url, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${adminKey}` },
      body: JSON.stringify(descriptor),
    });

    if (!write.ok) {
      console.error(`  ✗ ${tenant.slug}@${chainId}: PUT /v1/admin/tx-mappings returned ${write.status} ${await write.text()}`);
      failures += 1;
      continue;
    }

    // Read back rather than trusting the write: the stored descriptor is re-validated on read, and
    // one that no longer parses is reported as `valid: false` rather than refused — which in the
    // wallet presents as raw calldata, the exact failure this step exists to prevent.
    const readBack = await fetch(url, { headers: { authorization: `Bearer ${adminKey}` } });
    if (!readBack.ok) {
      console.error(`  ✗ ${tenant.slug}@${chainId}: GET /v1/admin/tx-mappings returned ${readBack.status}`);
      failures += 1;
      continue;
    }
    const stored = await readBack.json();
    if (!stored.valid) {
      console.error(`  ✗ ${tenant.slug}@${chainId}: stored mapping is invalid — ${JSON.stringify(stored.issues)}`);
      failures += 1;
      continue;
    }

    const formats = Object.keys(stored.descriptor?.display?.formats ?? {}).length;
    console.log(`  ✓ ${tenant.slug}@${chainId}: mapping published for ${contract} (${formats} function formats)`);
  }
}

if (failures > 0) {
  console.error(`\ntransaction-display provisioning FAILED for ${failures} tenant/chain pair(s) — the demo will show raw calldata`);
  process.exit(1);
}

console.log(`\nTransaction display mappings published for every demo tenant on chains ${CHAIN_IDS.join(', ')}.`);
