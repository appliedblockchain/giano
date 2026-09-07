import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex } from 'viem';
import { decodeFunctionData } from 'viem';

/**
 * Policy pipeline for relayed user operations. Every rule produces an audit entry;
 * the full list is persisted on the userop_log row whether accepted or rejected.
 */

export type PolicyRuleResult = {
  rule: string;
  passed: boolean;
  detail?: string;
};

export type PolicyDecision = {
  allowed: boolean;
  results: PolicyRuleResult[];
  /** First failing rule's human-readable reason. */
  rejectReason?: string;
};

/**
 * Extracts the tenant id a sponsored operation names, from the paymaster authorisation header.
 *
 * `paymasterData` is everything after the EntryPoint's 20+16+16 prefix; the Giano layout is
 * `version(1) ‖ tenantId(16) ‖ …`. Anything that is not that layout returns null — this is a
 * cross-check, not a parser, and a paymaster with a different data format is not a mismatch.
 */
export function decodeSponsoredTenantId(paymasterData: Hex | undefined): Hex | null {
  if (!paymasterData || paymasterData.length < 2 + 2 + 32) return null;
  const body = paymasterData.slice(2);
  if (body.slice(0, 2) !== '01') return null;
  return `0x${body.slice(2, 34)}`;
}

export type PolicyConfig = {
  maxCallGas: bigint;
  maxVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  /** lowercase addresses; empty = no restriction */
  allowedTargets: string[];
  /** lowercase addresses; empty = no restriction */
  allowedPaymasters: string[];
  /**
   * The tenant this session belongs to, as the 16-byte id the paymaster bills. When present, an
   * operation sponsored by Giano's paymaster must name it.
   */
  sponsorshipTenantId?: Hex;
};

export type PolicyUserOp = {
  sender: Address;
  callData: Hex;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymaster?: Address;
  paymasterData?: Hex;
};

/** Decodes execute/executeBatch calldata into target addresses. Unknown selectors → null. */
export function decodeCallTargets(callData: Hex): Address[] | null {
  try {
    const decoded = decodeFunctionData({ abi: gianoSmartWalletAbi, data: callData });
    if (decoded.functionName === 'execute') {
      return [decoded.args[0] as Address];
    }
    if (decoded.functionName === 'executeBatch') {
      return (decoded.args[0] as readonly { target: Address }[]).map((call) => call.target);
    }
    return null;
  } catch {
    return null;
  }
}

export function evaluatePolicy(userOp: PolicyUserOp, sessionWalletAddress: string, config: PolicyConfig): PolicyDecision {
  const results: PolicyRuleResult[] = [];
  const fail = (rule: string, detail: string) => results.push({ rule, passed: false, detail });
  const pass = (rule: string, detail?: string) => results.push({ rule, passed: true, detail });

  // 1. sender binding: the op must be from the session credential's wallet
  if (userOp.sender.toLowerCase() !== sessionWalletAddress.toLowerCase()) {
    fail('sender-binding', `sender ${userOp.sender} does not match session wallet ${sessionWalletAddress}`);
  } else {
    pass('sender-binding');
  }

  // 2. gas caps
  if (userOp.callGasLimit > config.maxCallGas) {
    fail('call-gas-cap', `callGasLimit ${userOp.callGasLimit} > cap ${config.maxCallGas}`);
  } else {
    pass('call-gas-cap');
  }
  if (userOp.verificationGasLimit > config.maxVerificationGas) {
    fail('verification-gas-cap', `verificationGasLimit ${userOp.verificationGasLimit} > cap ${config.maxVerificationGas}`);
  } else {
    pass('verification-gas-cap');
  }

  // 3. fee caps
  if (userOp.maxFeePerGas > config.maxFeePerGas) {
    fail('max-fee-cap', `maxFeePerGas ${userOp.maxFeePerGas} > cap ${config.maxFeePerGas}`);
  } else {
    pass('max-fee-cap');
  }
  if (userOp.maxPriorityFeePerGas > config.maxPriorityFeePerGas) {
    fail('priority-fee-cap', `maxPriorityFeePerGas ${userOp.maxPriorityFeePerGas} > cap ${config.maxPriorityFeePerGas}`);
  } else {
    pass('priority-fee-cap');
  }

  // 4. target allowlist (only when configured)
  if (config.allowedTargets.length > 0) {
    const targets = decodeCallTargets(userOp.callData);
    if (targets === null) {
      fail('target-allowlist', 'callData is not a decodable execute/executeBatch call');
    } else {
      const disallowed = targets.filter((t) => !config.allowedTargets.includes(t.toLowerCase()));
      if (disallowed.length > 0) {
        fail('target-allowlist', `targets not allowed: ${disallowed.join(', ')}`);
      } else {
        pass('target-allowlist', `targets: ${targets.join(', ')}`);
      }
    }
  } else {
    pass('target-allowlist', 'no restriction configured');
  }

  // 5. paymaster allowlist (only when configured)
  if (config.allowedPaymasters.length > 0) {
    if (!userOp.paymaster) {
      pass('paymaster-allowlist', 'no paymaster in op');
    } else if (!config.allowedPaymasters.includes(userOp.paymaster.toLowerCase())) {
      fail('paymaster-allowlist', `paymaster not allowed: ${userOp.paymaster}`);
    } else {
      pass('paymaster-allowlist');
    }
  } else {
    pass('paymaster-allowlist', 'no restriction configured');
  }

  // 6. Sponsored-tenant cross-check. The paymaster already enforces this on chain — the tenant is
  //    inside the authorisation signature — so this is defence in depth: it catches a service bug
  //    or a tampered operation before the bundler sees it, and it costs a slice of bytes.
  const sponsoredTenant = decodeSponsoredTenantId(userOp.paymasterData);
  if (!config.sponsorshipTenantId || !sponsoredTenant) {
    pass('sponsored-tenant-match', sponsoredTenant ? 'no session tenant to compare against' : 'not a Giano-sponsored operation');
  } else if (sponsoredTenant.toLowerCase() !== config.sponsorshipTenantId.toLowerCase()) {
    fail('sponsored-tenant-match', `operation bills tenant ${sponsoredTenant}, session belongs to ${config.sponsorshipTenantId}`);
  } else {
    pass('sponsored-tenant-match');
  }

  const firstFailure = results.find((r) => !r.passed);
  return {
    allowed: !firstFailure,
    results,
    rejectReason: firstFailure ? `${firstFailure.rule}: ${firstFailure.detail}` : undefined,
  };
}
