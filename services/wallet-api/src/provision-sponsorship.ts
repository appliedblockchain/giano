/**
 * Installs one tenant's sponsorship rules through the real admin API.
 *
 * The deployable counterpart of `e2e/devnet/provision-sponsorship.mjs`, which hardcodes the e2e
 * tenants' admin keys and reads `e2e/devnet/addresses.json` (INFRASTRUCTURE §16.3). Everything
 * here comes from the environment instead: tenant slug, chain ids and rules in, a
 * `PUT /v1/admin/sponsorship` out. Run by `aws ecs run-task` against the one-shot task definition
 * in `infra/iac/ecs_tasks_oneshot.tf`, once per tenant.
 *
 * Rules go in the way a tenant would put them in — a `PUT` with that tenant's own admin key —
 * rather than through a seeding path that would then have to be disabled in production. "A tenant
 * with no configuration gets no sponsorship" therefore stays true for real tenants because it is
 * true here too, and `TENANTS_SEED` keeps its declarative meaning: a restart cannot revert a
 * tenant's edit.
 *
 * Fails loudly and with a non-zero exit. An environment that cannot sponsor must announce it here,
 * where an operator is watching, rather than at a user's first transaction — where it presents as
 * "every transaction is refused", which looks exactly like a bug in the wallet.
 */
import { z } from 'zod';
import { sponsorshipConfigSchema } from './services/sponsorship-config.js';
import { tenantsSeedSchema } from './services/tenants.js';

const fail = (message: string): never => {
  console.error(message);
  process.exit(1);
};

const required = (name: string): string => process.env[name] ?? fail(`${name} is required`);

const apiUrl = required('WALLET_API_URL').replace(/\/$/, '');
const tenantSlug = required('TENANT_SLUG');

/**
 * Rules are per (tenant, chain) and never inherited (MC-67), so a deployment serving two chains
 * needs two writes. Accepting a list rather than demanding one run per chain keeps that a property
 * of the configuration instead of something an operator has to remember at the command line.
 */
const chainIds = required('CHAIN_ID')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean)
  .map((value) => {
    const chainId = Number(value);
    if (!Number.isInteger(chainId) || chainId <= 0) fail(`CHAIN_ID contains "${value}", which is not a chain id`);
    return chainId;
  });
if (chainIds.length === 0) fail('CHAIN_ID is required');

/**
 * Validated here as well as by the API, because the two failures read very differently: a typo
 * caught locally names the field, while a 400 arriving after the run has started reads as the
 * environment rejecting the operator.
 */
const config = (() => {
  const raw = required('SPONSORSHIP_CONFIG');
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (error) {
    return fail(`SPONSORSHIP_CONFIG is not valid JSON: ${(error as Error).message}`);
  }
  const parsed = sponsorshipConfigSchema.safeParse(json);
  if (!parsed.success) {
    return fail(
      `SPONSORSHIP_CONFIG is not a valid rule set:\n${parsed.error.issues
        .map((issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`)
        .join('\n')}`,
    );
  }
  return parsed.data;
})();

/**
 * The admin key is read from the same secret that provisions the tenant, so there is exactly one
 * place a key is written down. Never logged, and never echoed back by the API.
 */
const adminKey = (() => {
  const raw = required('TENANTS_SEED');
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (error) {
    return fail(`TENANTS_SEED is not valid JSON: ${(error as Error).message}`);
  }
  const seeds = tenantsSeedSchema.safeParse(json);
  if (!seeds.success) {
    return fail(
      `TENANTS_SEED is not a valid tenant seed:\n${seeds.error.issues
        .map((issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`)
        .join('\n')}`,
    );
  }
  const tenant = seeds.data.find((seed) => seed.slug === tenantSlug);
  if (!tenant) {
    return fail(`TENANTS_SEED has no tenant "${tenantSlug}" — known slugs: ${seeds.data.map((s) => s.slug).join(', ')}`);
  }
  if (tenant.adminKeys.length === 0) fail(`tenant "${tenantSlug}" has no admin keys, so its rules cannot be written`);
  return tenant.adminKeys[0]!;
})();

/**
 * Optional, and a cross-check rather than an input: the provisioner writes rules, it does not
 * choose a paymaster. A mismatch means this task and the API disagree about which contract holds
 * the tenant's balance, which is worth catching before someone funds the wrong address.
 */
const expectedPaymaster = process.env.SPONSORSHIP_PAYMASTER_ADDRESS?.toLowerCase();

/**
 * Registration and funding are chain operations that happen outside this task, so an environment
 * being provisioned before it is funded is legitimate. It is still a failure by default: rules
 * installed against an unfunded tenant sponsor nothing, and a green run that leaves every
 * transaction refused is the outcome this task exists to prevent.
 */
const requireFunded = (process.env.SPONSORSHIP_REQUIRE_FUNDED ?? 'true') !== 'false';

const authorized = { authorization: `Bearer ${adminKey}` };

async function waitForReady(attempts = 120): Promise<{ status: string; sponsorship?: string }> {
  let last = '';
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const response = await fetch(`${apiUrl}/readyz`);
      if (response.ok) return (await response.json()) as { status: string; sponsorship?: string };
      last = `${response.status} ${await response.text()}`;
      // A persistent 503 is a real failure, not a not-yet: report it rather than spin for a minute.
      if (response.status === 503 && attempt > 20) break;
    } catch (error) {
      last = (error as Error).message;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return fail(`${apiUrl}/readyz never became ready: ${last}`);
}

const ready = await waitForReady();
console.log(`wallet-api ready: ${JSON.stringify(ready)}`);
if (ready.sponsorship !== 'ok') {
  fail(
    `wallet-api reports sponsorship as "${ready.sponsorship ?? 'absent'}" — rules written now would be stored and ` +
      'never applied. Check SPONSORSHIP_ENABLED, the signer configuration and the chain descriptors.',
  );
}

const errorBody = z.object({ error: z.string().optional(), message: z.string().optional() }).passthrough();
const describe = async (response: Response) => {
  const text = await response.text();
  const parsed = errorBody.safeParse(JSON.parse(text || '{}'));
  return parsed.success && parsed.data.message ? `${response.status} ${parsed.data.message}` : `${response.status} ${text}`;
};

let failures = 0;
const failChain = (chainId: number, message: string) => {
  console.error(`  ✗ ${tenantSlug}@${chainId}: ${message}`);
  failures += 1;
};

for (const chainId of chainIds) {
  const write = await fetch(`${apiUrl}/v1/admin/sponsorship?chainId=${chainId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', ...authorized },
    body: JSON.stringify(config),
  });
  if (!write.ok) {
    failChain(chainId, `PUT /v1/admin/sponsorship returned ${await describe(write)}`);
    continue;
  }
  console.log(`  ✓ ${tenantSlug}@${chainId}: sponsorship rules installed`);

  // Read back rather than trusting the write: the stored value is re-validated on read, and a row
  // that no longer parses means no sponsorship — exactly the silent failure this step prevents.
  const readBack = await fetch(`${apiUrl}/v1/admin/sponsorship?chainId=${chainId}`, { headers: authorized });
  if (!readBack.ok) {
    failChain(chainId, `GET /v1/admin/sponsorship returned ${await describe(readBack)}`);
    continue;
  }
  const stored = (await readBack.json()) as { configured: boolean; valid: boolean; config: { enabled?: boolean } };
  if (!stored.configured || !stored.valid || stored.config.enabled !== config.enabled) {
    failChain(chainId, `read-back says configured=${stored.configured} valid=${stored.valid} enabled=${stored.config.enabled}`);
    continue;
  }

  const balance = await fetch(`${apiUrl}/v1/admin/sponsorship/balance?chainId=${chainId}`, { headers: authorized });
  if (!balance.ok) {
    failChain(chainId, `GET /v1/admin/sponsorship/balance returned ${await describe(balance)}`);
    continue;
  }
  const position = (await balance.json()) as {
    paymasterAddress: string;
    registered: boolean;
    balanceWei: string;
    availableWei: string;
    feeWei: string;
    fundingInstructions: { to: string; call: string };
  };

  if (expectedPaymaster && position.paymasterAddress.toLowerCase() !== expectedPaymaster) {
    failChain(
      chainId,
      `the API sponsors through ${position.paymasterAddress} but SPONSORSHIP_PAYMASTER_ADDRESS says ${expectedPaymaster} — ` +
        'one of the two is pointed at the wrong contract, and funding the wrong one loses the money',
    );
    continue;
  }

  const funding = `${position.fundingInstructions.call} on ${position.fundingInstructions.to}`;
  if (!position.registered) {
    const message = `not registered on the paymaster at ${position.paymasterAddress} — register it, then ${funding}`;
    if (requireFunded) failChain(chainId, message);
    else console.warn(`  ! ${tenantSlug}@${chainId}: ${message}`);
    continue;
  }
  if (BigInt(position.availableWei) === 0n) {
    const message = `registered but holds no available balance — nothing can be sponsored until ${funding}`;
    if (requireFunded) failChain(chainId, message);
    else console.warn(`  ! ${tenantSlug}@${chainId}: ${message}`);
    continue;
  }

  console.log(
    `    balance ${position.balanceWei} wei, available ${position.availableWei} wei, fee ${position.feeWei} wei`,
  );
}

if (failures > 0) {
  console.error(`\nsponsorship provisioning FAILED for ${tenantSlug} on ${failures} of ${chainIds.length} chain(s)`);
  process.exit(1);
}

console.log(`\nSponsorship provisioned for "${tenantSlug}" on chains ${chainIds.join(', ')}.`);
