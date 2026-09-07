import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex } from 'viem';
import { encodeFunctionData } from 'viem';
import { describe, expect, it } from 'vitest';
import {
  checkWalletManagementCap,
  parseSponsorshipConfig,
  sponsorshipConfigSchema,
  walletManagementEnabled,
  type SponsorshipConfig,
} from '../src/services/sponsorship-config.js';
import {
  computeMaxCost,
  computeOverheadBound,
  decodeInnerCalls,
  evaluateSponsorship,
  type BalanceView,
  type CandidateOperation,
  type EvaluationInput,
} from '../src/services/sponsorship-rules.js';

const WALLET = '0x1111111111111111111111111111111111111234' as Address;
const TOKEN = '0x3333333333333333333333333333333333333333' as Address;
const OTHER = '0x4444444444444444444444444444444444444444' as Address;

const TRANSFER = '0xa9059cbb' as Hex; // transfer(address,uint256)
const APPROVE = '0x095ea7b3' as Hex; // approve(address,uint256)

function execute(target: Address, data: Hex = '0x'): Hex {
  return encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'execute', args: [target, 0n, data] });
}

function executeBatch(calls: Array<{ target: Address; data: Hex }>): Hex {
  return encodeFunctionData({
    abi: gianoSmartWalletAbi,
    functionName: 'executeBatch',
    args: [calls.map((call) => ({ target: call.target, value: 0n, data: call.data }))],
  });
}

const candidate: CandidateOperation = {
  sender: WALLET,
  callData: execute(TOKEN, TRANSFER),
  callGasLimit: 200_000n,
  verificationGasLimit: 500_000n,
  preVerificationGas: 50_000n,
  maxFeePerGas: 2_000_000_000n,
  paymasterVerificationGasLimit: 150_000n,
  paymasterPostOpGasLimit: 100_000n,
};

const overhead = { postOpGasAllowance: 40_000n, penaltyBps: 1000n };
const FEE_WEI = 100_000_000_000_000n; // 0.0001 ETH
/** The platform's wallet-management cap. Generous here; the cap's own tests narrow it. */
const WM_CAP_WEI = 10n ** 17n;

const generousBalance: BalanceView = { balanceWei: 10n ** 18n, reservedWei: 0n, deficitWei: 0n };

function config(overrides: Partial<SponsorshipConfig> = {}): SponsorshipConfig {
  return sponsorshipConfigSchema.parse({
    enabled: true,
    maxCostPerTxWei: (10n ** 17n).toString(),
    allowlist: [{ contract: TOKEN, functions: [TRANSFER] }],
    ...overrides,
  });
}

function evaluate(overrides: Partial<EvaluationInput> = {}) {
  return evaluateSponsorship({
    candidate,
    config: config(),
    balance: generousBalance,
    feeWei: FEE_WEI,
    overhead,
    walletManagementCapWei: WM_CAP_WEI,
    sessionWalletAddress: WALLET,
    ...overrides,
  });
}

describe('cost arithmetic', () => {
  it('mirrors the EntryPoint prefund formula', () => {
    // (preVerificationGas + verification + pmVerification + pmPostOp + callGas) × maxFeePerGas
    const expected = (50_000n + 500_000n + 150_000n + 100_000n + 200_000n) * 2_000_000_000n;
    expect(computeMaxCost(candidate)).toBe(expected);
  });

  it('bounds the overhead from the execution gas limits rather than a flat figure', () => {
    // A flat figure under-covers exactly when the client over-estimates its call gas, because the
    // EntryPoint's penalty scales with that over-estimate.
    const modest = computeOverheadBound(candidate, overhead);
    const wasteful = computeOverheadBound({ ...candidate, callGasLimit: 3_000_000n }, overhead);
    expect(wasteful).toBeGreaterThan(modest);

    const executionGas = 200_000n + 100_000n;
    expect(modest).toBe(2_000_000_000n * (40_000n + (executionGas * 1000n) / 10_000n));
  });
});

describe('call decoding', () => {
  it('decodes a single execute', () => {
    expect(decodeInnerCalls(execute(TOKEN, TRANSFER))).toEqual([{ target: TOKEN, selector: TRANSFER }]);
  });

  it('decodes a batch', () => {
    const calls = decodeInnerCalls(executeBatch([{ target: TOKEN, data: TRANSFER }, { target: OTHER, data: APPROVE }]));
    expect(calls).toEqual([{ target: TOKEN, selector: TRANSFER }, { target: OTHER, selector: APPROVE }]);
  });

  it('reports a bare value transfer as having no selector rather than inventing one', () => {
    expect(decodeInnerCalls(execute(TOKEN, '0x'))).toEqual([{ target: TOKEN, selector: null }]);
  });

  it('returns null for calldata it cannot read, so the caller refuses rather than guesses', () => {
    expect(decodeInnerCalls('0xdeadbeef')).toBeNull();
    expect(decodeInnerCalls('0x')).toBeNull();
  });
});

describe('deny by default', () => {
  it('refuses a tenant with no configuration', () => {
    const decision = evaluate({ config: sponsorshipConfigSchema.parse({}) });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('sponsorship-disabled');
  });

  it('refuses an enabled configuration with an empty allowlist', () => {
    // The schema will not produce this, but a row written by an older version could, and it must
    // not be read as "allow everything".
    const decision = evaluate({ config: { enabled: true, maxCostPerTxWei: '1000000000000000000', allowlist: [] } });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('no-sponsorship-config');
  });

  it('distinguishes an unparseable configuration from a switched-off one', () => {
    const off = evaluate({ config: sponsorshipConfigSchema.parse({}) });
    const broken = evaluate({ configUnparseable: true });
    expect(off.reason).toBe('sponsorship-disabled');
    expect(broken.reason).toBe('no-sponsorship-config');
    expect(broken.allowed).toBe(false);
  });
});

describe('allowlists', () => {
  it('allows a listed contract and function', () => {
    const decision = evaluate();
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBeUndefined();
  });

  it('refuses an unlisted contract', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: execute(OTHER, TRANSFER) } });
    expect(decision.reason).toBe('contract-not-allowed');
    expect(decision.detail).toContain(OTHER);
  });

  it('refuses an unlisted function on a listed contract, distinguishably', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: execute(TOKEN, APPROVE) } });
    expect(decision.reason).toBe('function-not-allowed');
  });

  it("accepts any function when the entry says 'all'", () => {
    const decision = evaluate({
      config: config({ allowlist: [{ contract: TOKEN, functions: 'all' }] }),
      candidate: { ...candidate, callData: execute(TOKEN, APPROVE) },
    });
    expect(decision.allowed).toBe(true);
  });

  // Partial sponsorship is not something the chain can express, so one bad call refuses the lot.
  it('refuses a whole batch for one disallowed call', () => {
    const decision = evaluate({
      candidate: { ...candidate, callData: executeBatch([{ target: TOKEN, data: TRANSFER }, { target: OTHER, data: TRANSFER }]) },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('contract-not-allowed');
  });

  it('allows a batch where every call is permitted', () => {
    const decision = evaluate({
      config: config({ allowlist: [{ contract: TOKEN, functions: [TRANSFER] }, { contract: OTHER, functions: 'all' }] }),
      candidate: { ...candidate, callData: executeBatch([{ target: TOKEN, data: TRANSFER }, { target: OTHER, data: APPROVE }]) },
    });
    expect(decision.allowed).toBe(true);
  });

  it('refuses calldata it cannot decode', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: '0xdeadbeef' } });
    expect(decision.allowed).toBe(false);
    expect(decision.results.find((r) => r.rule === 'decodable-calls')?.passed).toBe(false);
  });

  it('refuses a bare value transfer to a contract restricted by selector', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: execute(TOKEN, '0x') } });
    expect(decision.reason).toBe('function-not-allowed');
  });
});

describe('wallet management', () => {
  const selfCall = execute(WALLET, '0x0f0f3f95'); // addOwnerAddress-shaped

  // The requirement this file exists to pin down: a user acquiring a second device holds no
  // native token and no way to obtain one, so recovery has to be sponsored — and it must not
  // depend on the tenant having listed anything, because a tenant that forgot would break
  // recovery for its own users.
  it('sponsors a self-call by default, with nothing about the wallet in the allowlist', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: selfCall } });
    expect(decision.allowed).toBe(true);
    expect(decision.isWalletManagement).toBe(true);
    expect(decision.capWei).toBe(WM_CAP_WEI);
    expect(decision.capSource).toBe('platform');
  });

  it('sponsors it when the tenant has no walletManagement block at all', () => {
    const bare = config();
    expect(bare.walletManagement).toBeUndefined();
    expect(evaluate({ config: bare, candidate: { ...candidate, callData: selfCall } }).allowed).toBe(true);
  });

  it('refuses only on an explicit opt-out', () => {
    const decision = evaluate({
      config: config({ walletManagement: { enabled: false } }),
      candidate: { ...candidate, callData: selfCall },
    });
    expect(decision.reason).toBe('wallet-management-not-sponsored');
  });

  it('applies the platform cap rather than the tenant\'s ordinary one', () => {
    const decision = evaluate({
      config: config({ maxCostPerTxWei: (10n ** 18n).toString() }),
      candidate: { ...candidate, callData: selfCall },
      walletManagementCapWei: 1n,
    });
    expect(decision.reason).toBe('cost-exceeds-cap');
    expect(decision.capWei).toBe(1n);
    expect(decision.capSource).toBe('platform');
  });

  it('lets a tenant lower the platform cap', () => {
    const decision = evaluate({
      config: config({ walletManagement: { enabled: true, maxCostPerTxWei: '1' } }),
      candidate: { ...candidate, callData: selfCall },
    });
    expect(decision.reason).toBe('cost-exceeds-cap');
    expect(decision.capWei).toBe(1n);
    expect(decision.capSource).toBe('wallet-management-tenant');
  });

  // A stored row written while the platform cap was higher must not outrank the current cap:
  // the whole point of the cap being the platform's is that a tenant cannot raise it.
  it('never lets a stored tenant cap exceed the current platform cap', () => {
    const decision = evaluate({
      config: config({ walletManagement: { enabled: true, maxCostPerTxWei: (10n ** 18n).toString() } }),
      candidate: { ...candidate, callData: selfCall },
      walletManagementCapWei: 5n,
    });
    expect(decision.capWei).toBe(5n);
    expect(decision.capSource).toBe('platform');
  });

  // Detected by shape, not by a selector list. That cuts both ways, which is why it is the right
  // test: a self-administration function added later can neither become sponsorable by omission
  // nor become *un*sponsorable by omission.
  it('detects wallet management structurally, whatever the selector', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: execute(WALLET, '0xffffffff') } });
    expect(decision.isWalletManagement).toBe(true);
    expect(decision.allowed).toBe(true);
  });

  it('does not require a tenant to allow-list its own users wallet addresses', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: selfCall } });
    expect(decision.results.find((r) => r.rule === 'contract-allowlist')?.passed).toBe(true);
  });

  // One charge, and the chain cannot split it, so the tighter of the two caps governs.
  it('applies the tighter cap to a batch that mixes a self-call with an application call', () => {
    const mixed = executeBatch([
      { target: WALLET, data: '0x0f0f3f95' },
      { target: TOKEN, data: TRANSFER },
    ]);
    const decision = evaluate({
      config: config({ maxCostPerTxWei: '1' }),
      candidate: { ...candidate, callData: mixed },
    });
    expect(decision.reason).toBe('cost-exceeds-cap');
    expect(decision.capWei).toBe(1n);
    expect(decision.capSource).toBe('tenant');
  });

  it('still checks the allowlist for the application half of a mixed batch', () => {
    const mixed = executeBatch([
      { target: WALLET, data: '0x0f0f3f95' },
      { target: OTHER, data: TRANSFER },
    ]);
    const decision = evaluate({ candidate: { ...candidate, callData: mixed } });
    expect(decision.reason).toBe('contract-not-allowed');
  });
});

describe('cost cap', () => {
  it('counts gas, fee and overhead together, not gas alone', () => {
    const maxCost = computeMaxCost(candidate);
    const overheadWei = computeOverheadBound(candidate, overhead);

    // A cap that covers the gas exactly must still refuse, because the fee and the overhead are
    // also charged to the tenant.
    const tight = evaluate({ config: config({ maxCostPerTxWei: maxCost.toString() }) });
    expect(tight.reason).toBe('cost-exceeds-cap');

    const exact = evaluate({ config: config({ maxCostPerTxWei: (maxCost + FEE_WEI + overheadWei).toString() }) });
    expect(exact.allowed).toBe(true);
  });

  it('reports the components separately, so a tenant can see what it was refused for', () => {
    const decision = evaluate({ config: config({ maxCostPerTxWei: '1' }) });
    expect(decision.detail).toMatch(/gas \d+ \+ fee \d+ \+ overhead \d+/);
  });
});

describe('balance', () => {
  it('refuses when available balance cannot cover the charge', () => {
    const decision = evaluate({ balance: { balanceWei: 1n, reservedWei: 0n, deficitWei: 0n } });
    expect(decision.reason).toBe('insufficient-balance');
  });

  // The case D5 exists for: the balance alone is enough, but what is already in flight is not.
  it('counts outstanding reservations against the balance', () => {
    const charge = evaluate().maxChargeWei;
    const enough = evaluate({ balance: { balanceWei: charge, reservedWei: 0n, deficitWei: 0n } });
    expect(enough.allowed).toBe(true);

    const spokenFor = evaluate({ balance: { balanceWei: charge, reservedWei: 1n, deficitWei: 0n } });
    expect(spokenFor.reason).toBe('insufficient-balance');
    expect(spokenFor.detail).toContain('reserved');
  });

  it('reports a deficit distinguishably from an empty balance', () => {
    const decision = evaluate({ balance: { balanceWei: 10n ** 18n, reservedWei: 0n, deficitWei: 1n } });
    expect(decision.reason).toBe('tenant-in-deficit');
  });
});

describe('sender binding', () => {
  it('refuses an operation for a wallet the session does not own', () => {
    const decision = evaluate({ sessionWalletAddress: OTHER });
    expect(decision.reason).toBe('not-your-wallet');
  });
});

describe('audit trail', () => {
  // "Why was this refused" has to be answerable without re-running anything, and the first
  // failure alone does not tell you what else was wrong.
  it('records every rule, not only the one that decided', () => {
    const decision = evaluate({ candidate: { ...candidate, callData: execute(OTHER, TRANSFER) } });
    const rules = decision.results.map((r) => r.rule);
    expect(rules).toEqual([
      'sponsorship-enabled',
      'sender-binding',
      'decodable-calls',
      'wallet-management',
      'contract-allowlist',
      'function-allowlist',
      'max-cost',
      'sufficient-balance',
    ]);
  });

  it('reports the first failure as the reason even when several rules fail', () => {
    const decision = evaluate({
      sessionWalletAddress: OTHER,
      candidate: { ...candidate, callData: execute(OTHER, TRANSFER) },
    });
    expect(decision.reason).toBe('not-your-wallet');
    expect(decision.results.filter((r) => !r.passed).length).toBeGreaterThan(1);
  });
});

describe('configuration schema', () => {
  it('normalises a function signature to a selector at write time', () => {
    const parsed = sponsorshipConfigSchema.parse({
      enabled: true,
      maxCostPerTxWei: '1',
      allowlist: [{ contract: TOKEN, functions: ['transfer(address,uint256)'] }],
    });
    expect(parsed.allowlist[0].functions).toEqual([TRANSFER]);
  });

  it('lowercases addresses so matching never depends on checksum casing', () => {
    const parsed = sponsorshipConfigSchema.parse({
      enabled: true,
      maxCostPerTxWei: '1',
      allowlist: [{ contract: TOKEN.toUpperCase().replace('0X', '0x'), functions: 'all' }],
    });
    expect(parsed.allowlist[0].contract).toBe(TOKEN.toLowerCase());
  });

  it('requires a cap and a non-empty allowlist once enabled', () => {
    const result = sponsorshipConfigSchema.safeParse({ enabled: true });
    expect(result.success).toBe(false);
    const paths = result.success ? [] : result.error.issues.map((i) => i.path.join('.'));
    expect(paths).toContain('maxCostPerTxWei');
    expect(paths).toContain('allowlist');
  });

  // The one permissive default in the schema, and the only one that should be: wallet management
  // must be sponsored, so its absence cannot mean denied.
  it('treats an absent walletManagement block as sponsored', () => {
    const parsed = sponsorshipConfigSchema.parse({
      enabled: true,
      maxCostPerTxWei: '1',
      allowlist: [{ contract: TOKEN, functions: 'all' }],
    });
    expect(parsed.walletManagement).toBeUndefined();
    expect(walletManagementEnabled(parsed)).toBe(true);
  });

  it('defaults walletManagement.enabled to true when the block is present without it', () => {
    const parsed = sponsorshipConfigSchema.parse({
      enabled: true,
      maxCostPerTxWei: '1',
      allowlist: [{ contract: TOKEN, functions: 'all' }],
      walletManagement: { maxCostPerTxWei: '5' },
    });
    expect(parsed.walletManagement?.enabled).toBe(true);
  });

  it('rejects a tenant wallet-management cap above the platform cap, rather than clamping it', () => {
    const parsed = config({ walletManagement: { enabled: true, maxCostPerTxWei: '100' } });
    expect(checkWalletManagementCap(parsed, 100n)).toEqual([]);
    const issues = checkWalletManagementCap(parsed, 99n);
    expect(issues).toHaveLength(1);
    expect(issues[0].path).toBe('walletManagement.maxCostPerTxWei');
  });

  // A row stored when the platform cap was higher must still *parse* — degrading it is the rules
  // engine's job, and failing to parse would take the tenant's whole configuration down with it.
  it('still parses a stored cap above the current platform cap', () => {
    const stored = { enabled: true, maxCostPerTxWei: '1', allowlist: [{ contract: TOKEN, functions: 'all' }], walletManagement: { enabled: true, maxCostPerTxWei: '999' } };
    expect(parseSponsorshipConfig(stored).ok).toBe(true);
  });

  it('has no way to express "any contract"', () => {
    expect(sponsorshipConfigSchema.safeParse({ enabled: true, maxCostPerTxWei: '1', allowlist: ['*'] }).success).toBe(false);
    expect(
      sponsorshipConfigSchema.safeParse({ enabled: true, maxCostPerTxWei: '1', allowlist: [{ contract: '*', functions: 'all' }] }).success,
    ).toBe(false);
  });

  it('rejects unknown keys rather than silently dropping them', () => {
    const result = sponsorshipConfigSchema.safeParse({ enabled: true, maxCostPerTxWei: '1', allowlist: [{ contract: TOKEN, functions: 'all' }], sponsorEverything: true });
    expect(result.success).toBe(false);
  });

  it('rejects a duplicate contract instead of picking a winner', () => {
    const result = sponsorshipConfigSchema.safeParse({
      enabled: true,
      maxCostPerTxWei: '1',
      allowlist: [{ contract: TOKEN, functions: [TRANSFER] }, { contract: TOKEN, functions: 'all' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects a wei value that is not a decimal string', () => {
    expect(sponsorshipConfigSchema.safeParse({ enabled: true, maxCostPerTxWei: '0x1', allowlist: [{ contract: TOKEN, functions: 'all' }] }).success).toBe(false);
    expect(sponsorshipConfigSchema.safeParse({ enabled: true, maxCostPerTxWei: -1, allowlist: [{ contract: TOKEN, functions: 'all' }] }).success).toBe(false);
  });

  // An unparseable stored value must degrade to *no sponsorship*, never to permissive, and it
  // must not throw where a caller might catch and shrug it off.
  it('degrades an unparseable stored configuration to deny-all', () => {
    const parsed = parseSponsorshipConfig({ enabled: true, allowlist: 'everything' });
    expect(parsed.ok).toBe(false);
    expect(parsed.config).toEqual({ enabled: false, allowlist: [] });
    if (!parsed.ok) expect(parsed.issues.length).toBeGreaterThan(0);
  });

  it('accepts a valid stored configuration unchanged', () => {
    const stored = { enabled: true, maxCostPerTxWei: '1000', allowlist: [{ contract: TOKEN, functions: 'all' }] };
    const parsed = parseSponsorshipConfig(stored);
    expect(parsed.ok).toBe(true);
    expect(parsed.config.enabled).toBe(true);
  });
});
