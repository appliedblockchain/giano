import { formatEther } from 'viem';
import type { HealthCheck, HealthLevel, HealthReport, PaymasterOverview } from './types';

/**
 * Deployment health.
 *
 * The thresholds and verdicts are deliberately the same ones `giano-doctor` applies, so a panel
 * and the CI gate cannot disagree about whether a deployment is usable. They are pure functions of
 * an overview: no RPC here, which means a UI can re-evaluate them against data it already has, and
 * a test can drive every branch without a chain.
 */

/** Below this, sponsored operations start failing in ways that look like client bugs. */
export const LOW_DEPOSIT_WEI = 20_000_000_000_000_000n; // 0.02 ETH

/** A validating paymaster needs a stake before bundlers will accept its operations at all. */
export const MIN_STAKE_WEI = 100_000_000_000_000_000n; // 0.1 ETH

const worst = (levels: readonly HealthLevel[]): HealthLevel =>
  levels.includes('fail') ? 'fail' : levels.includes('warn') ? 'warn' : 'ok';

export function assessHealth(overview: PaymasterOverview): HealthReport {
  const checks: HealthCheck[] = [];
  const { config, stake, solvency, tenants, signers, roles } = overview;

  // --- solvency: the property everything else rests on ----------------------------------------
  checks.push(
    solvency.holds
      ? {
          id: 'solvency',
          level: 'ok',
          label: 'accounting invariant (Σ balances + treasury ≤ deposit)',
          detail: `${formatEther(solvency.claimsWei)} ≤ ${formatEther(solvency.depositWei)} ETH, ${formatEther(solvency.slackWei)} ETH unattributed slack`,
        }
      : {
          id: 'solvency',
          level: 'fail',
          label: 'accounting invariant breached',
          detail: `claims ${formatEther(solvency.claimsWei)} ETH exceed the deposit ${formatEther(solvency.depositWei)} ETH`,
          remedy: 'This is an insolvency. Stop issuing sponsorships and investigate before anything else.',
        },
  );

  // --- stake and deposit ----------------------------------------------------------------------
  checks.push(
    stake.staked && stake.stakeWei >= MIN_STAKE_WEI
      ? { id: 'stake', level: 'ok', label: 'paymaster staked', detail: `${formatEther(stake.stakeWei)} ETH` }
      : {
          id: 'stake',
          level: 'fail',
          label: 'paymaster stake',
          detail: stake.staked ? `${formatEther(stake.stakeWei)} ETH, below the ${formatEther(MIN_STAKE_WEI)} ETH minimum` : 'not staked',
          remedy: 'Bundlers reject an unstaked validating paymaster, which reads as a client bug. Call addStake (STAKE_ADMIN_ROLE).',
        },
  );

  checks.push(
    solvency.depositWei >= LOW_DEPOSIT_WEI
      ? { id: 'deposit', level: 'ok', label: 'EntryPoint deposit', detail: `${formatEther(solvency.depositWei)} ETH` }
      : {
          id: 'deposit',
          level: 'fail',
          label: 'EntryPoint deposit',
          detail: `${formatEther(solvency.depositWei)} ETH, below the ${formatEther(LOW_DEPOSIT_WEI)} ETH working minimum`,
          remedy: 'Fund a tenant — depositFor is the only way funds enter, and it credits the deposit too.',
        },
  );

  if (stake.withdrawTime > 0) {
    checks.push({
      id: 'stake-unlocking',
      level: 'warn',
      label: 'stake is unlocking',
      detail: `withdrawable from unix time ${stake.withdrawTime}`,
      remedy: 'An unlocked stake stops bundlers accepting operations. Re-stake unless this is a deliberate wind-down.',
    });
  }

  // --- signing keys ---------------------------------------------------------------------------
  checks.push(
    signers.length > 0
      ? { id: 'signers', level: 'ok', label: 'sponsorship signing keys', detail: signers.join(', ') }
      : {
          id: 'signers',
          level: 'fail',
          label: 'sponsorship signing keys',
          detail: 'none authorised',
          remedy: 'Nothing can be authorised without one. Call addSigner (SIGNER_ADMIN_ROLE).',
        },
  );

  // --- role topology --------------------------------------------------------------------------
  const defaultAdmin = roles.find((entry) => entry.name === 'DEFAULT_ADMIN_ROLE');
  checks.push(
    (defaultAdmin?.holders.length ?? 0) === 0
      ? { id: 'no-superuser', level: 'ok', label: 'no DEFAULT_ADMIN_ROLE holder', detail: 'there is no superuser' }
      : {
          id: 'no-superuser',
          level: 'fail',
          label: 'DEFAULT_ADMIN_ROLE is held',
          detail: `${defaultAdmin?.holders.join(', ')} — this is a superuser by another name`,
          remedy: 'Revoke it. The design grants every power through its own named role instead.',
        },
  );

  for (const name of ['ROLE_ADMIN', 'UPGRADER_ROLE'] as const) {
    const entry = roles.find((candidate) => candidate.name === name);
    const count = entry?.holders.length ?? 0;
    checks.push(
      count === 1
        ? { id: `role-${name}`, level: 'warn', label: `${name} holder`, detail: `${entry?.holders[0]} — verify this is the timelock` }
        : {
            id: `role-${name}`,
            level: 'fail',
            label: `${name} holders`,
            detail: `${count} holder(s)${count > 0 ? `: ${entry?.holders.join(', ')}` : ''} — expected exactly one`,
            remedy: 'Both roles should rest with a single timelock. More than one holder widens the blast radius; none makes the contract unmaintainable.',
          },
    );
  }

  // --- operational state ----------------------------------------------------------------------
  checks.push(
    config.paused
      ? {
          id: 'paused',
          level: 'warn',
          label: 'accepting new sponsorships',
          detail: 'PAUSED',
          remedy: 'Withdrawals still work. Unpause when the incident that motivated it is closed (PAUSER_ROLE).',
        }
      : { id: 'paused', level: 'ok', label: 'accepting new sponsorships', detail: 'not paused' },
  );

  // --- tenants --------------------------------------------------------------------------------
  const inDeficit = tenants.filter((tenant) => tenant.deficit > 0n);
  if (inDeficit.length > 0) {
    checks.push({
      id: 'tenant-deficits',
      level: 'fail',
      label: `${inDeficit.length} tenant(s) in deficit`,
      detail: inDeficit.map((tenant) => `${tenant.uuid} owes ${formatEther(tenant.deficit)} ETH`).join('; '),
      remedy: 'A tenant in deficit cannot transact. Funding it clears the deficit first, then credits the remainder.',
    });
  }

  const funded = tenants.filter((tenant) => tenant.balance > 0n);
  if (tenants.length === 0) {
    checks.push({
      id: 'tenants-funded',
      level: 'warn',
      label: 'registered tenants',
      detail: 'none',
      remedy: 'Register one with registerTenant (TENANT_ADMIN_ROLE) before expecting sponsorship to work.',
    });
  } else {
    checks.push(
      funded.length > 0
        ? {
            id: 'tenants-funded',
            level: 'ok',
            label: 'funded tenants',
            detail: `${funded.length} of ${tenants.length}, ${formatEther(solvency.tenantBalancesWei)} ETH total`,
          }
        : {
            id: 'tenants-funded',
            level: 'fail',
            label: 'funded tenants',
            detail: `none of ${tenants.length}`,
            remedy: 'A deployment is not complete until at least one tenant holds a balance.',
          },
    );
  }

  return { level: worst(checks.map((check) => check.level)), checks };
}
