/**
 * Installs the demo tenants' sponsorship rules through the real admin API.
 *
 * Deliberately *not* baked into the devnet state and deliberately *not* part of TENANTS_SEED.
 *
 * Rules are a tenant's own to edit, so they go in the way a tenant would put them in: a `PUT` to
 * `/v1/admin/sponsorship` with the tenant's own admin key. That means there is no dev-only seeding
 * mechanism that would then have to be disabled in production — "a tenant with no configuration
 * gets no sponsorship" stays true for real tenants because it is true here too. It also means
 * `TENANTS_SEED` keeps its declarative meaning: a restart cannot revert a tenant's edit.
 *
 * The configs are deliberately generous — the demo contracts allow-listed, a high cost cap, a
 * large balance — so that fixtures which merely need a sponsored transaction never trip a rule
 * they were not written to exercise. The sponsorship suite narrows the config per scenario through
 * this same endpoint.
 *
 * Fails loudly: a stack that cannot sponsor must fail to come up rather than come up broken.
 *
 * Usage:  WALLET_API_URL=http://api.localhost node e2e/devnet/provision-sponsorship.mjs
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
// Compose sets WALLET_API_URL to the container address; the default is for host-side runs,
// where the wallet-api answers to the name portless publishes (see e2e/origins.mjs).
const apiUrl = (process.env.WALLET_API_URL ?? 'http://api.localhost').replace(/\/$/, '');
const addresses = JSON.parse(fs.readFileSync(path.join(dir, 'addresses.json'), 'utf8'));

/** Admin keys as `TENANTS_SEED` provisions them in deploy/docker-compose.e2e.yml. */
const TENANT_ADMIN_KEYS = {
  stock: process.env.STOCK_ADMIN_KEY ?? 'e2e-admin-key-stock',
  byo: process.env.BYO_ADMIN_KEY ?? 'e2e-admin-key-byo00',
};

/**
 * What the demo sponsors. The demo ERC-20 in full; wallet management needs no entry here at all,
 * because it is governed by platform policy rather than by a tenant's allowlist — the "add a
 * passkey on a new device" flow is the case where a user is least likely to hold a native token,
 * so a tenant must not be able to break it by leaving something out of a list.
 */
function demoConfig() {
  return {
    enabled: true,
    // 0.5 ETH per transaction: far above anything the demo does, and low enough that the cap is
    // still a real rule rather than a decoration.
    maxCostPerTxWei: (5n * 10n ** 17n).toString(),
    allowlist: [{ contract: addresses.testErc20, functions: 'all' }],
    // No `walletManagement` block: its absence means sponsored, which is the point. The cap comes
    // from SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI, set generously for this stack because the baked
    // devnet state leaves the base fee high (~100 gwei after the deployment blocks) and a tight cap
    // would refuse fixtures for a reason that has nothing to do with what they test.
    //
    // A tenant may add the block to *lower* that cap, or to switch sponsorship of it off entirely;
    // it can never raise it.
    lowBalanceThresholdWei: (10n ** 18n).toString(),
  };
}

async function waitForReady(attempts = 120) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(`${apiUrl}/readyz`);
      if (response.ok) return await response.json();
      // 503 with a signer problem is a real failure, not a not-yet: report it rather than spin.
      if (response.status === 503 && i > 20) {
        const body = await response.text();
        throw new Error(`wallet-api is not ready after ${i} attempts: ${body}`);
      }
    } catch (error) {
      if (i === attempts - 1) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`${apiUrl}/readyz never became ready`);
}

const ready = await waitForReady();
console.log(`wallet-api ready: ${JSON.stringify(ready)}`);

if (ready.sponsorship !== 'ok') {
  throw new Error(
    `wallet-api reports sponsorship as "${ready.sponsorship ?? 'absent'}" — the demo is supposed to transact through the ` +
      'production paymaster. Check SPONSORSHIP_ENABLED and the signer configuration.',
  );
}

let failures = 0;

for (const tenant of addresses.tenants) {
  const adminKey = TENANT_ADMIN_KEYS[tenant.slug];
  if (!adminKey) {
    console.error(`  ✗ ${tenant.slug}: no admin key known for this tenant`);
    failures += 1;
    continue;
  }

  const config = demoConfig();
  const write = await fetch(`${apiUrl}/v1/admin/sponsorship`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${adminKey}` },
    body: JSON.stringify(config),
  });

  if (!write.ok) {
    console.error(`  ✗ ${tenant.slug}: PUT /v1/admin/sponsorship returned ${write.status} ${await write.text()}`);
    failures += 1;
    continue;
  }
  console.log(`  ✓ ${tenant.slug}: sponsorship rules installed`);

  // Read back rather than trusting the write: the stored value is re-validated on read, and a row
  // that no longer parses means no sponsorship — which is exactly the silent failure this whole
  // step exists to prevent.
  const readBack = await fetch(`${apiUrl}/v1/admin/sponsorship`, { headers: { authorization: `Bearer ${adminKey}` } });
  const stored = await readBack.json();
  if (!stored.configured || !stored.valid || stored.config.enabled !== true) {
    console.error(`  ✗ ${tenant.slug}: read-back says configured=${stored.configured} valid=${stored.valid}`);
    failures += 1;
    continue;
  }

  const balance = await fetch(`${apiUrl}/v1/admin/sponsorship/balance`, { headers: { authorization: `Bearer ${adminKey}` } });
  if (!balance.ok) {
    console.error(`  ✗ ${tenant.slug}: GET /v1/admin/sponsorship/balance returned ${balance.status}`);
    failures += 1;
    continue;
  }
  const position = await balance.json();
  if (!position.registered) {
    console.error(`  ✗ ${tenant.slug}: not registered on the paymaster at ${position.paymasterAddress}`);
    failures += 1;
    continue;
  }
  if (BigInt(position.availableWei) === 0n) {
    console.error(`  ✗ ${tenant.slug}: registered but holds no available balance — nothing can be sponsored`);
    failures += 1;
    continue;
  }
  console.log(`    balance ${position.balanceWei} wei, available ${position.availableWei} wei, fee ${position.feeWei} wei`);
}

if (failures > 0) {
  console.error(`\nsponsorship provisioning FAILED for ${failures} tenant(s) — this stack cannot sponsor`);
  process.exit(1);
}

console.log('\nSponsorship provisioned for every demo tenant.');
