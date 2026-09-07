import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex } from 'viem';
import { decodeFunctionData, slice, size } from 'viem';
import { walletManagementEnabled, type SponsorshipConfig } from './sponsorship-config.js';

/**
 * The sponsorship rules engine.
 *
 * A pure function, no I/O. That is what lets the wallet's pre-approval check and the
 * authoritative pre-signature check share one implementation — two implementations of the same
 * rules would drift, and the drift would show up as a transaction refused after the user had
 * already been asked to approve it.
 *
 * Every rule is recorded whether it passed or not, even after the decision is settled, because
 * "why was this refused" has to be answerable without re-running anything.
 */

export type SponsorshipRuleResult = {
  rule: string;
  passed: boolean;
  detail?: string;
};

/** Stable, machine-readable refusal reasons. The wallet keys its copy off these, never off prose. */
export type SponsorshipRefusalReason =
  | 'sponsorship-disabled'
  | 'no-sponsorship-config'
  | 'contract-not-allowed'
  | 'function-not-allowed'
  | 'wallet-management-not-sponsored'
  | 'cost-exceeds-cap'
  | 'insufficient-balance'
  | 'tenant-in-deficit'
  | 'not-your-wallet';

export type SponsorshipDecision = {
  allowed: boolean;
  results: SponsorshipRuleResult[];
  reason?: SponsorshipRefusalReason;
  detail?: string;
  /** What the operation would cost the tenant in total: gas + fee + overhead. */
  maxChargeWei: bigint;
  feeWei: bigint;
  overheadWei: bigint;
  /** The per-transaction cap that applied — the tenant's own, the platform's, or the lower of both. */
  capWei?: bigint;
  /**
   * Where that cap came from. Recorded because "how much are we spending on wallet management, and
   * for whom" has to be answerable from the decision table before the question of who pays for it
   * is decided, not after.
   */
  capSource?: 'tenant' | 'platform' | 'wallet-management-tenant';
  /** True when the operation contains a call from the wallet to itself. */
  isWalletManagement: boolean;
};

export type CandidateOperation = {
  sender: Address;
  callData: Hex;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  /** Present only when the operation also deploys the account. Part of the operation's hash. */
  factory?: Address;
  factoryData?: Hex;
};

/** What the ledger knows, at the moment of asking. */
export type BalanceView = {
  balanceWei: bigint;
  reservedWei: bigint;
  deficitWei: bigint;
};

export type OverheadParams = {
  /** Gas units the settlement step's own execution is charged at. */
  postOpGasAllowance: bigint;
  /** Basis points of the execution gas limits charged as a bound on the EntryPoint's penalty. */
  penaltyBps: bigint;
};

export type EvaluationInput = {
  candidate: CandidateOperation;
  config: SponsorshipConfig;
  balance: BalanceView;
  /** The fee in force for this tenant, read from the contract so what is pinned is what is charged. */
  feeWei: bigint;
  overhead: OverheadParams;
  /**
   * The platform's cap on wallet-management operations.
   *
   * Platform configuration, not the tenant's, because wallet management is sponsored whatever the
   * tenant's allowlist says — so the tenant cannot be the only thing bounding it. A tenant may
   * lower this figure and never raise it.
   */
  walletManagementCapWei: bigint;
  /** The wallet address the session's credential owns. */
  sessionWalletAddress: Address;
  /** True when the stored configuration failed to parse, which is not the same as it being off. */
  configUnparseable?: boolean;
};

/**
 * Mirrors the EntryPoint's own prefund arithmetic. Getting this wrong in the *optimistic*
 * direction would reserve less than the chain can charge, which is how a balance overdraws.
 */
export function computeMaxCost(candidate: CandidateOperation): bigint {
  const verificationGas =
    candidate.verificationGasLimit + candidate.paymasterVerificationGasLimit + candidate.paymasterPostOpGasLimit;
  return (candidate.preVerificationGas + verificationGas + candidate.callGasLimit) * candidate.maxFeePerGas;
}

/**
 * The same formula the contract applies at settlement, so the reservation and the eventual charge
 * cannot drift apart in shape. Charging a bound on the penalty rather than a flat figure is what
 * makes it hold when a client grossly over-estimates its call gas — which is precisely the case
 * that drives the penalty.
 */
export function computeOverheadBound(candidate: CandidateOperation, overhead: OverheadParams): bigint {
  const executionGasLimit = candidate.callGasLimit + candidate.paymasterPostOpGasLimit;
  return candidate.maxFeePerGas * (overhead.postOpGasAllowance + (executionGasLimit * overhead.penaltyBps) / 10_000n);
}

type InnerCall = { target: Address; selector: Hex | null };

/**
 * Decodes the account's own `execute` / `executeBatch` calldata.
 *
 * Anything else is refused rather than guessed: an operation whose targets we cannot read is an
 * operation whose allowlist we cannot check, and guessing would mean sponsoring it.
 */
export function decodeInnerCalls(callData: Hex): InnerCall[] | null {
  try {
    const decoded = decodeFunctionData({ abi: gianoSmartWalletAbi, data: callData });
    if (decoded.functionName === 'execute') {
      const [target, , data] = decoded.args as readonly [Address, bigint, Hex];
      return [{ target, selector: selectorOf(data) }];
    }
    if (decoded.functionName === 'executeBatch') {
      const calls = decoded.args[0] as readonly { target: Address; value: bigint; data: Hex }[];
      return calls.map((call) => ({ target: call.target, selector: selectorOf(call.data) }));
    }
    return null;
  } catch {
    return null;
  }
}

function selectorOf(data: Hex): Hex | null {
  return size(data) >= 4 ? (slice(data, 0, 4).toLowerCase() as Hex) : null;
}

export function evaluateSponsorship(input: EvaluationInput): SponsorshipDecision {
  const { candidate, config, balance, feeWei, overhead, sessionWalletAddress } = input;

  const results: SponsorshipRuleResult[] = [];
  const pass = (rule: string, detail?: string) => results.push({ rule, passed: true, detail });
  const fail = (rule: string, detail: string) => results.push({ rule, passed: false, detail });

  const maxCostWei = computeMaxCost(candidate);
  const overheadWei = computeOverheadBound(candidate, overhead);
  const maxChargeWei = maxCostWei + feeWei + overheadWei;

  let reason: SponsorshipRefusalReason | undefined;
  let detail: string | undefined;
  /** First failure decides, but every rule still runs and is still recorded. */
  const refuse = (rule: string, why: SponsorshipRefusalReason, message: string) => {
    fail(rule, message);
    if (!reason) {
      reason = why;
      detail = message;
    }
  };

  // 1. Is sponsorship on at all, and is the configuration usable?
  if (input.configUnparseable) {
    refuse('sponsorship-enabled', 'no-sponsorship-config', 'the stored sponsorship configuration could not be parsed');
  } else if (!config.enabled) {
    refuse('sponsorship-enabled', 'sponsorship-disabled', 'sponsorship is switched off for this tenant');
  } else if (config.allowlist.length === 0) {
    refuse('sponsorship-enabled', 'no-sponsorship-config', 'no contracts are allow-listed');
  } else {
    pass('sponsorship-enabled');
  }

  // 2. The operation must be for the session's own wallet.
  if (candidate.sender.toLowerCase() !== sessionWalletAddress.toLowerCase()) {
    refuse(
      'sender-binding',
      'not-your-wallet',
      `sender ${candidate.sender} is not this session's wallet ${sessionWalletAddress}`,
    );
  } else {
    pass('sender-binding');
  }

  // 3. Decode, or refuse. Never guess.
  const calls = decodeInnerCalls(candidate.callData);
  if (calls === null) {
    refuse('decodable-calls', 'contract-not-allowed', 'callData is not a decodable execute/executeBatch call');
  } else if (calls.length === 0) {
    refuse('decodable-calls', 'contract-not-allowed', 'the operation contains no calls');
  } else {
    pass('decodable-calls', `${calls.length} inner call(s)`);
  }

  // 4. Wallet management, detected structurally: a call from the wallet to itself is
  //    addOwner / removeOwner / upgradeToAndCall. Detecting it by shape rather than by a
  //    selector list cuts both ways, which is why it is the right test — a self-administration
  //    function added to the wallet later can neither become sponsorable by omission nor become
  //    *unsponsorable* by omission.
  //
  //    These transactions are sponsored. A user acquiring a second device holds no native token
  //    and has no way to obtain one, so an unsponsored recovery path does not work for the users
  //    who need it. That is why the rule is the platform's and not an allowlist entry: a tenant
  //    that forgot to list something must not be able to break account recovery.
  const selfCalls = (calls ?? []).filter((call) => call.target.toLowerCase() === candidate.sender.toLowerCase());
  const isWalletManagement = selfCalls.length > 0;
  const hasApplicationCalls = (calls ?? []).length > selfCalls.length;

  const tenantCapWei = config.maxCostPerTxWei ? BigInt(config.maxCostPerTxWei) : undefined;
  let capWei = tenantCapWei;
  let capSource: SponsorshipDecision['capSource'] = tenantCapWei === undefined ? undefined : 'tenant';

  if (!isWalletManagement) {
    pass('wallet-management', 'not a wallet-management operation');
  } else if (!walletManagementEnabled(config)) {
    // Only reachable when the tenant has explicitly switched it off — never by leaving something
    // out of a list, which is the whole point of the rule living here.
    refuse(
      'wallet-management',
      'wallet-management-not-sponsored',
      'this tenant has explicitly switched off sponsorship of wallet-management transactions',
    );
  } else {
    // The tenant may lower the platform cap and never raise it, so the lower of the two governs
    // even for a row written while the platform cap was higher.
    const tenantWmCap = config.walletManagement?.maxCostPerTxWei;
    const wmCapWei =
      tenantWmCap === undefined
        ? input.walletManagementCapWei
        : min(BigInt(tenantWmCap), input.walletManagementCapWei);
    const wmCapSource: SponsorshipDecision['capSource'] =
      tenantWmCap !== undefined && BigInt(tenantWmCap) <= input.walletManagementCapWei
        ? 'wallet-management-tenant'
        : 'platform';

    if (hasApplicationCalls && tenantCapWei !== undefined && tenantCapWei < wmCapWei) {
      // A mixed batch is one charge and the chain cannot split it, so the tighter cap governs.
      capWei = tenantCapWei;
      capSource = 'tenant';
      pass('wallet-management', `sponsored; mixed batch, so the tenant's tighter cap of ${capWei} wei applies`);
    } else {
      capWei = wmCapWei;
      capSource = wmCapSource;
      pass('wallet-management', `sponsored under the ${wmCapSource === 'platform' ? 'platform' : "tenant's lowered"} cap of ${capWei} wei`);
    }
  }

  // 5 & 6. Contract and function allowlists. A batch is all-or-nothing: partial sponsorship is
  //        not something the chain can express, so one disallowed call refuses the whole
  //        operation.
  const byContract = new Map(config.allowlist.map((entry) => [entry.contract, entry.functions]));
  const contractFailures: string[] = [];
  const functionFailures: string[] = [];

  for (const call of calls ?? []) {
    // A self-call is governed by rule 4, not by the allowlist — a tenant should not have to
    // allow-list its users' own wallet addresses, which it cannot know in advance.
    if (call.target.toLowerCase() === candidate.sender.toLowerCase()) continue;

    const allowed = byContract.get(call.target.toLowerCase() as Address);
    if (!allowed) {
      contractFailures.push(call.target);
      continue;
    }
    if (allowed === 'all') continue;
    if (call.selector === null) {
      functionFailures.push(`${call.target}: a bare value transfer with no selector`);
      continue;
    }
    if (!allowed.includes(call.selector)) {
      functionFailures.push(`${call.target}.${call.selector}`);
    }
  }

  if (contractFailures.length > 0) {
    refuse('contract-allowlist', 'contract-not-allowed', `not allow-listed: ${contractFailures.join(', ')}`);
  } else {
    pass('contract-allowlist');
  }

  if (functionFailures.length > 0) {
    refuse('function-allowlist', 'function-not-allowed', `function not permitted: ${functionFailures.join(', ')}`);
  } else {
    pass('function-allowlist');
  }

  // 7. The per-transaction cost cap, applied to the *whole* charge. Capping gas alone would let
  //    the fee and the overhead push the real cost past what the tenant agreed to.
  if (capWei === undefined) {
    refuse('max-cost', 'no-sponsorship-config', 'no per-transaction cost cap is configured');
  } else if (maxChargeWei > capWei) {
    refuse(
      'max-cost',
      'cost-exceeds-cap',
      `maximum charge ${maxChargeWei} wei (gas ${maxCostWei} + fee ${feeWei} + overhead ${overheadWei}) exceeds the ` +
        `${capSource ?? 'tenant'} cap of ${capWei} wei`,
    );
  } else {
    pass('max-cost', `${maxChargeWei} wei of a ${capWei} wei ${capSource ?? 'tenant'} cap`);
  }

  // 8. Available balance. A deficit is money the pooled deposit already absorbed on this
  //    tenant's behalf, so it stops further authorisation until the tenant funds.
  if (balance.deficitWei > 0n) {
    refuse('sufficient-balance', 'tenant-in-deficit', `an outstanding deficit of ${balance.deficitWei} wei must be funded first`);
  } else {
    const availableWei = balance.balanceWei - balance.reservedWei;
    if (availableWei < maxChargeWei) {
      refuse(
        'sufficient-balance',
        'insufficient-balance',
        `available ${availableWei} wei (balance ${balance.balanceWei} − reserved ${balance.reservedWei}) cannot cover ${maxChargeWei} wei`,
      );
    } else {
      pass('sufficient-balance', `${availableWei} wei available`);
    }
  }

  return {
    allowed: reason === undefined,
    results,
    reason,
    detail,
    maxChargeWei,
    feeWei,
    overheadWei,
    capWei,
    capSource,
    isWalletManagement,
  };
}

function min(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}
