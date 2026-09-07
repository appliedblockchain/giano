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

export type PolicyConfig = {
  maxCallGas: bigint;
  maxVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  /** lowercase addresses; empty = no restriction */
  allowedTargets: string[];
  /** lowercase addresses; empty = no restriction */
  allowedPaymasters: string[];
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

  const firstFailure = results.find((r) => !r.passed);
  return {
    allowed: !firstFailure,
    results,
    rejectReason: firstFailure ? `${firstFailure.rule}: ${firstFailure.detail}` : undefined,
  };
}
