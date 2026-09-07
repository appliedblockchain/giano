import { encodeFunctionData } from 'viem';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import { describe, expect, it } from 'vitest';
import { decodeCallTargets, decodeSponsoredTenantId, evaluatePolicy, type PolicyConfig, type PolicyUserOp } from '../src/services/userop-policy.js';

const WALLET = '0x1111111111111111111111111111111111111234';
const TARGET = '0x3333333333333333333333333333333333333333';
const OTHER = '0x4444444444444444444444444444444444444444';
const PAYMASTER = '0x15a2075f2407427C5dd0BDe9d1966c48BD70E2f2';

const baseConfig: PolicyConfig = {
  maxCallGas: 1_000_000n,
  maxVerificationGas: 1_000_000n,
  maxFeePerGas: 100n * 10n ** 9n,
  maxPriorityFeePerGas: 100n * 10n ** 9n,
  allowedTargets: [],
  allowedPaymasters: [],
};

const executeCallData = encodeFunctionData({
  abi: gianoSmartWalletAbi,
  functionName: 'execute',
  args: [TARGET, 0n, '0x'],
});

const baseOp: PolicyUserOp = {
  sender: WALLET,
  callData: executeCallData,
  callGasLimit: 100_000n,
  verificationGasLimit: 100_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 10n * 10n ** 9n,
  maxPriorityFeePerGas: 1n * 10n ** 9n,
};

describe('decodeCallTargets', () => {
  it('decodes execute', () => {
    expect(decodeCallTargets(executeCallData)).toEqual([TARGET]);
  });

  it('decodes executeBatch', () => {
    const data = encodeFunctionData({
      abi: gianoSmartWalletAbi,
      functionName: 'executeBatch',
      args: [[{ target: TARGET, value: 0n, data: '0x' }, { target: OTHER, value: 1n, data: '0xdead' }]],
    });
    expect(decodeCallTargets(data)).toEqual([TARGET, OTHER]);
  });

  it('returns null for undecodable calldata', () => {
    expect(decodeCallTargets('0xdeadbeef')).toBeNull();
  });
});

describe('evaluatePolicy', () => {
  it('accepts a compliant op and records every rule as an audit row', () => {
    const decision = evaluatePolicy(baseOp, WALLET, baseConfig);
    expect(decision.allowed).toBe(true);
    // Eight rules since the sponsored-tenant cross-check joined them.
    expect(decision.results).toHaveLength(8);
    expect(decision.results.every((r) => r.passed)).toBe(true);
  });

  it('rejects sender not matching the session wallet', () => {
    const decision = evaluatePolicy({ ...baseOp, sender: OTHER }, WALLET, baseConfig);
    expect(decision.allowed).toBe(false);
    expect(decision.rejectReason).toContain('sender-binding');
  });

  it('is case-insensitive on the sender binding', () => {
    const decision = evaluatePolicy({ ...baseOp, sender: WALLET.toUpperCase().replace('0X', '0x') as never }, WALLET, baseConfig);
    expect(decision.allowed).toBe(true);
  });

  it('rejects over-cap gas and fees', () => {
    expect(evaluatePolicy({ ...baseOp, callGasLimit: 2_000_000n }, WALLET, baseConfig).rejectReason).toContain('call-gas-cap');
    expect(evaluatePolicy({ ...baseOp, verificationGasLimit: 2_000_000n }, WALLET, baseConfig).rejectReason).toContain('verification-gas-cap');
    expect(evaluatePolicy({ ...baseOp, maxFeePerGas: 200n * 10n ** 9n }, WALLET, baseConfig).rejectReason).toContain('max-fee-cap');
    expect(evaluatePolicy({ ...baseOp, maxPriorityFeePerGas: 200n * 10n ** 9n }, WALLET, baseConfig).rejectReason).toContain('priority-fee-cap');
  });

  it('enforces the target allowlist when configured', () => {
    const config = { ...baseConfig, allowedTargets: [TARGET.toLowerCase()] };
    expect(evaluatePolicy(baseOp, WALLET, config).allowed).toBe(true);

    const badData = encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'execute', args: [OTHER, 0n, '0x'] });
    const rejected = evaluatePolicy({ ...baseOp, callData: badData }, WALLET, config);
    expect(rejected.allowed).toBe(false);
    expect(rejected.rejectReason).toContain('target-allowlist');
  });

  it('rejects undecodable calldata when a target allowlist is configured', () => {
    const config = { ...baseConfig, allowedTargets: [TARGET.toLowerCase()] };
    const rejected = evaluatePolicy({ ...baseOp, callData: '0xdeadbeef' }, WALLET, config);
    expect(rejected.allowed).toBe(false);
    expect(rejected.rejectReason).toContain('not a decodable');
  });

  it('enforces the paymaster allowlist when configured', () => {
    const config = { ...baseConfig, allowedPaymasters: [TARGET.toLowerCase()] };
    expect(evaluatePolicy({ ...baseOp, paymaster: TARGET }, WALLET, config).allowed).toBe(true);
    expect(evaluatePolicy({ ...baseOp, paymaster: OTHER }, WALLET, config).allowed).toBe(false);
    // op without paymaster passes even with allowlist configured
    expect(evaluatePolicy(baseOp, WALLET, config).allowed).toBe(true);
  });
});

describe('sponsored-tenant cross-check', () => {
  const TENANT_A_ID = '0x11111111111141118111111111111111';
  const TENANT_B_ID = '0x22222222222242228222222222222222';

  /** The Giano authorisation header: version(1) ‖ tenantId(16) ‖ … */
  const paymasterData = (tenantId: string) => `${tenantId.replace('0x', '0x01')}${'ff'.repeat(48)}` as `0x${string}`;

  it('decodes the tenant a sponsored operation names', () => {
    expect(decodeSponsoredTenantId(paymasterData(TENANT_A_ID))).toBe(TENANT_A_ID);
  });

  it('returns null for anything that is not the Giano layout', () => {
    // A paymaster with a different data format is not a mismatch — it is simply not ours.
    expect(decodeSponsoredTenantId(undefined)).toBeNull();
    expect(decodeSponsoredTenantId('0x')).toBeNull();
    expect(decodeSponsoredTenantId(`0x02${'11'.repeat(16)}`)).toBeNull();
    expect(decodeSponsoredTenantId('0x01abcd')).toBeNull();
  });

  /**
   * The paymaster already enforces this on chain — the tenant is inside the authorisation
   * signature. This is defence in depth: it catches a service bug or a tampered operation before
   * the bundler sees it.
   */
  it('rejects an operation that bills a tenant the session does not belong to', () => {
    const decision = evaluatePolicy(
      { ...baseOp, paymaster: PAYMASTER, paymasterData: paymasterData(TENANT_B_ID) },
      WALLET,
      { ...baseConfig, sponsorshipTenantId: TENANT_A_ID },
    );
    expect(decision.allowed).toBe(false);
    expect(decision.rejectReason).toContain('sponsored-tenant-match');
  });

  it('accepts an operation that bills the session\'s own tenant', () => {
    const decision = evaluatePolicy(
      { ...baseOp, paymaster: PAYMASTER, paymasterData: paymasterData(TENANT_A_ID) },
      WALLET,
      { ...baseConfig, sponsorshipTenantId: TENANT_A_ID },
    );
    expect(decision.results.find((r) => r.rule === 'sponsored-tenant-match')?.passed).toBe(true);
  });

  it('passes an unsponsored operation through untouched', () => {
    const decision = evaluatePolicy(baseOp, WALLET, { ...baseConfig, sponsorshipTenantId: TENANT_A_ID });
    const rule = decision.results.find((r) => r.rule === 'sponsored-tenant-match');
    expect(rule?.passed).toBe(true);
    expect(rule?.detail).toContain('not a Giano-sponsored operation');
  });
});
