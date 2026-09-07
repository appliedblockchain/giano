import { parseEther } from 'viem';
import { describe, expect, it } from 'vitest';
import { assessHealth } from '../src/health';
import { DEFAULT_ADMIN_ROLE, PAYMASTER_ROLES } from '../src/roles';
import type { PaymasterOverview, RoleHolders, TenantView } from '../src/types';

const TIMELOCK = '0x1111111111111111111111111111111111111111' as const;
const SIGNER = '0x2222222222222222222222222222222222222222' as const;

function tenant(overrides: Partial<TenantView> = {}): TenantView {
  return {
    id: '0x3f2504e04f8911d39a0c0305e82c3301',
    uuid: '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
    registered: true,
    enabled: true,
    hasFeeOverride: false,
    withdrawAddress: TIMELOCK,
    balance: parseEther('1'),
    deficit: 0n,
    feeWeiOverride: 0n,
    effectiveFeeWei: parseEther('0.0001'),
    status: 'active',
    ...overrides,
  };
}

function roles(overrides: Partial<Record<string, readonly `0x${string}`[]>> = {}): readonly RoleHolders[] {
  const holders = (name: string, fallback: readonly `0x${string}`[]) => overrides[name] ?? fallback;
  return [
    { name: 'DEFAULT_ADMIN_ROLE', role: DEFAULT_ADMIN_ROLE, holders: holders('DEFAULT_ADMIN_ROLE', []) },
    { name: 'ROLE_ADMIN', role: PAYMASTER_ROLES.ROLE_ADMIN, holders: holders('ROLE_ADMIN', [TIMELOCK]) },
    { name: 'UPGRADER_ROLE', role: PAYMASTER_ROLES.UPGRADER_ROLE, holders: holders('UPGRADER_ROLE', [TIMELOCK]) },
  ];
}

function overview(overrides: Partial<PaymasterOverview> = {}): PaymasterOverview {
  const tenants = overrides.tenants ?? [tenant()];
  const tenantBalancesWei = tenants.reduce((sum, current) => sum + current.balance, 0n);
  const treasuryWei = parseEther('0.01');
  const depositWei = parseEther('5');

  return {
    address: '0x3333333333333333333333333333333333333333',
    chainId: 31337,
    config: {
      entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
      defaultFeeWei: parseEther('0.0001'),
      postOpGasAllowance: 40_000,
      penaltyBps: 1000,
      paused: false,
    },
    stake: { depositWei, stakeWei: parseEther('1'), staked: true, unstakeDelaySec: 86_400, withdrawTime: 0 },
    solvency: {
      tenantBalancesWei,
      treasuryWei,
      claimsWei: tenantBalancesWei + treasuryWei,
      depositWei,
      slackWei: depositWei - (tenantBalancesWei + treasuryWei),
      holds: true,
    },
    tenants,
    signers: [SIGNER],
    roles: roles(),
    ...overrides,
  };
}

const check = (report: ReturnType<typeof assessHealth>, id: string) => report.checks.find((candidate) => candidate.id === id);

describe('assessHealth', () => {
  it('passes a well-provisioned deployment, warning only that the authority is unverified', () => {
    const report = assessHealth(overview());

    expect(check(report, 'solvency')?.level).toBe('ok');
    expect(check(report, 'stake')?.level).toBe('ok');
    expect(check(report, 'deposit')?.level).toBe('ok');
    expect(check(report, 'signers')?.level).toBe('ok');
    expect(check(report, 'no-superuser')?.level).toBe('ok');
    expect(check(report, 'tenants-funded')?.level).toBe('ok');
    // ROLE_ADMIN / UPGRADER_ROLE holders can only be reported, not asserted, from on-chain data.
    expect(report.level).toBe('warn');
  });

  it('fails a breached invariant, which is an insolvency rather than a warning', () => {
    const base = overview();
    const report = assessHealth({
      ...base,
      solvency: { ...base.solvency, claimsWei: parseEther('99'), slackWei: -parseEther('94'), holds: false },
    });

    expect(check(report, 'solvency')?.level).toBe('fail');
    expect(check(report, 'solvency')?.remedy).toMatch(/Stop issuing sponsorships/i);
    expect(report.level).toBe('fail');
  });

  it('fails an unstaked paymaster, because bundlers reject it outright', () => {
    const base = overview();
    const report = assessHealth({ ...base, stake: { ...base.stake, staked: false, stakeWei: 0n } });

    expect(check(report, 'stake')?.level).toBe('fail');
    expect(check(report, 'stake')?.remedy).toMatch(/STAKE_ADMIN_ROLE/);
  });

  it('fails a stake below the working minimum even when it is technically staked', () => {
    const base = overview();
    const report = assessHealth({ ...base, stake: { ...base.stake, staked: true, stakeWei: parseEther('0.05') } });

    expect(check(report, 'stake')?.level).toBe('fail');
  });

  it('warns while the stake is unlocking, since that also stops bundlers', () => {
    const base = overview();
    const report = assessHealth({ ...base, stake: { ...base.stake, withdrawTime: 1_800_000_000 } });

    expect(check(report, 'stake-unlocking')?.level).toBe('warn');
  });

  it('fails a low deposit', () => {
    const base = overview();
    const report = assessHealth({ ...base, solvency: { ...base.solvency, depositWei: parseEther('0.001') } });

    expect(check(report, 'deposit')?.level).toBe('fail');
  });

  it('fails when no signing key is authorised, because nothing can be sponsored', () => {
    const report = assessHealth({ ...overview(), signers: [] });

    expect(check(report, 'signers')?.level).toBe('fail');
    expect(report.level).toBe('fail');
  });

  it('fails when DEFAULT_ADMIN_ROLE is held — that is a superuser by another name', () => {
    const report = assessHealth({ ...overview(), roles: roles({ DEFAULT_ADMIN_ROLE: [TIMELOCK] }) });

    expect(check(report, 'no-superuser')?.level).toBe('fail');
  });

  it.each([
    ['none', [] as readonly `0x${string}`[]],
    ['two', [TIMELOCK, SIGNER] as readonly `0x${string}`[]],
  ])('fails when ROLE_ADMIN has %s holders rather than exactly one', (_label, holders) => {
    const report = assessHealth({ ...overview(), roles: roles({ ROLE_ADMIN: holders }) });

    expect(check(report, 'role-ROLE_ADMIN')?.level).toBe('fail');
  });

  it('warns when paused, and says withdrawals still work', () => {
    const base = overview();
    const report = assessHealth({ ...base, config: { ...base.config, paused: true } });

    expect(check(report, 'paused')?.level).toBe('warn');
    expect(check(report, 'paused')?.remedy).toMatch(/Withdrawals still work/i);
  });

  it('fails a tenant in deficit and names it', () => {
    const report = assessHealth({ ...overview(), tenants: [tenant({ deficit: parseEther('0.5'), status: 'in-deficit' })] });

    expect(check(report, 'tenant-deficits')?.level).toBe('fail');
    expect(check(report, 'tenant-deficits')?.detail).toContain('3f2504e0-4f89-11d3-9a0c-0305e82c3301');
  });

  it('fails when no tenant holds a balance — a deployment is not complete until one does', () => {
    const report = assessHealth({ ...overview(), tenants: [tenant({ balance: 0n, status: 'unfunded' })] });

    expect(check(report, 'tenants-funded')?.level).toBe('fail');
  });

  it('warns rather than fails when there are no tenants at all', () => {
    const base = overview({ tenants: [] });
    const report = assessHealth(base);

    expect(check(report, 'tenants-funded')?.level).toBe('warn');
  });

  it('reports the worst level across every check', () => {
    const base = overview();
    const healthy = assessHealth(base);
    expect(healthy.level).toBe('warn');

    const broken = assessHealth({ ...base, signers: [] });
    expect(broken.level).toBe('fail');
  });
});
