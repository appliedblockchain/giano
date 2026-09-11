import { and, eq } from 'drizzle-orm';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import type { Address, Hex } from 'viem';
import { getUserOperationHash } from 'viem/account-abstraction';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import { sponsorshipDecisions, useropLog } from '../db/schema.js';
import type { ChainServices } from './chains.js';
import type { SessionContext } from './sessions.js';
import { mergePolicy, type Tenant } from './tenants.js';
import { evaluatePolicy, type PolicyRuleResult } from './userop-policy.js';

const hexData = z.string().regex(/^0x[0-9a-fA-F]*$/) as z.ZodType<Hex>;
const hexQuantity = z.string().regex(/^0x[0-9a-fA-F]+$/) as z.ZodType<Hex>;
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/) as z.ZodType<Address>;

/**
 * EntryPoint v0.7 user operation in JSON-RPC (hex) encoding. The EntryPoint address
 * is NEVER taken from the request — the server submits against its configured one.
 * (The old demo trusted `signedUserOp.account.entryPoint.address` — that hole is closed.)
 */
export const rpcUserOpSchema = z
  .object({
    sender: address,
    nonce: hexQuantity,
    callData: hexData,
    callGasLimit: hexQuantity,
    verificationGasLimit: hexQuantity,
    preVerificationGas: hexQuantity,
    maxFeePerGas: hexQuantity,
    maxPriorityFeePerGas: hexQuantity,
    signature: hexData,
    factory: address.optional(),
    factoryData: hexData.optional(),
    paymaster: address.optional(),
    paymasterVerificationGasLimit: hexQuantity.optional(),
    paymasterPostOpGasLimit: hexQuantity.optional(),
    paymasterData: hexData.optional(),
  })
  .strip();

export type RpcUserOp = z.infer<typeof rpcUserOpSchema>;

function toBigIntUserOp(op: RpcUserOp) {
  return {
    sender: op.sender,
    nonce: BigInt(op.nonce),
    callData: op.callData,
    callGasLimit: BigInt(op.callGasLimit),
    verificationGasLimit: BigInt(op.verificationGasLimit),
    preVerificationGas: BigInt(op.preVerificationGas),
    maxFeePerGas: BigInt(op.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas),
    signature: op.signature,
    ...(op.factory ? { factory: op.factory, factoryData: op.factoryData ?? '0x' } : {}),
    ...(op.paymaster
      ? {
          paymaster: op.paymaster,
          paymasterData: op.paymasterData ?? '0x',
          paymasterVerificationGasLimit: BigInt(op.paymasterVerificationGasLimit ?? '0x0'),
          paymasterPostOpGasLimit: BigInt(op.paymasterPostOpGasLimit ?? '0x0'),
        }
      : {}),
  };
}

export type RelayOutcome =
  | { kind: 'submitted'; userOperationHash: Hex; duplicate?: true }
  | { kind: 'rejected'; reason: string; policy: PolicyRuleResult[] }
  /** The hash is already logged for someone else — never say more than that (V9). */
  | { kind: 'conflict' };

export type RelayCaller = {
  session: SessionContext;
  tenant: Tenant | null;
  chain: ChainServices;
  log: FastifyBaseLogger;
};

export type UseropRelayOptions = {
  db: Db;
  config: AppConfig;
  /** Deployment-wide numeric caps. Address-valued defaults live on each chain descriptor (MC-61). */
  defaultPolicy: { maxCallGas: bigint; maxVerificationGas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint };
  metrics: FastifyInstance['metrics'];
};

/**
 * The relay pipeline — policy, audit log, idempotency, submission — shared by the REST
 * endpoint (`POST /v1/userops`) and the JSON-RPC bundler facade (`POST /v1/bundler`). One
 * implementation, so an operation cannot reach the bundler with fewer checks through one
 * door than through the other.
 */
export function createUseropRelay({ db, config, defaultPolicy, metrics }: UseropRelayOptions) {
  /**
   * Policy for one (tenant, chain), per §9.5: env caps ← the chain descriptor's own policy
   * ← the tenant's overrides for THAT chain. Address-valued fields never cross chains.
   */
  const tenantPolicy = (caller: Pick<RelayCaller, 'session' | 'tenant' | 'chain'>) => {
    const { chain } = caller;
    const chainDefaults = {
      maxCallGas: chain.descriptor.policy.maxCallGas ?? defaultPolicy.maxCallGas,
      maxVerificationGas: chain.descriptor.policy.maxVerificationGas ?? defaultPolicy.maxVerificationGas,
      maxFeePerGas: chain.descriptor.policy.maxFeePerGas ?? defaultPolicy.maxFeePerGas,
      maxPriorityFeePerGas: chain.descriptor.policy.maxPriorityFeePerGas ?? defaultPolicy.maxPriorityFeePerGas,
      allowedTargets: chain.descriptor.policy.allowedTargets,
      allowedPaymasters: chain.descriptor.policy.allowedPaymasters,
    };
    return {
      ...mergePolicy(chainDefaults, caller.tenant?.policy, chain.chainId),
      // The 16-byte id the paymaster bills, so `sponsored-tenant-match` can cross-check a sponsored
      // operation against the session that submitted it.
      sponsorshipTenantId: `0x${caller.session.tenantId.replace(/-/g, '')}` as Hex,
    };
  };

  /**
   * Light per-tenant relay limit (G5.2): a shared bundler and executor balance mean one
   * tenant must not be able to exhaust them for everyone. Hand-rolled fixed window
   * (in-memory, single-process — acceptable for this iteration) rather than
   * @fastify/rate-limit, because it must run AFTER requireSession resolved the tenant.
   *
   * One window per tenant, SHARED across chains (MC-63) and across both doors into the
   * relay: adding a chain or a second endpoint must not raise a tenant's effective ceiling.
   */
  const relayWindows = new Map<string, { windowStart: number; count: number }>();
  const takeRelaySlot = (caller: Pick<RelayCaller, 'session' | 'tenant' | 'chain'>): { ok: true } | { ok: false; max: number } => {
    const max = tenantPolicy(caller).relayRateLimitPerMinute ?? config.USEROP_RATE_LIMIT_PER_MINUTE;
    const now = Date.now();
    const window = relayWindows.get(caller.session.tenantId);
    if (!window || now - window.windowStart >= 60_000) {
      relayWindows.set(caller.session.tenantId, { windowStart: now, count: 1 });
      return { ok: true };
    }
    window.count += 1;
    if (window.count > max) {
      metrics.useropRelayed.inc({ status: 'rate-limited', tenant: caller.tenant?.slug ?? 'unknown', chain: String(caller.chain.chainId) });
      return { ok: false, max };
    }
    return { ok: true };
  };

  /** Throws only on a bundler failure (`BundlerRpcError` or a transport error), after logging it. */
  const relay = async (caller: RelayCaller, rpcOp: RpcUserOp): Promise<RelayOutcome> => {
    const stopTimer = metrics.useropLatency.startTimer();
    const { session, chain, log } = caller;
    const chainLabel = String(chain.chainId);
    const tenantSlug = caller.tenant?.slug ?? 'unknown';
    try {
      const userOp = toBigIntUserOp(rpcOp);

      // Hash is computed server-side against the RESOLVED chain and the server-configured
      // EntryPoint for that chain (MC-57) — never from an unvalidated value in the request
      // body, so the request cannot influence where this op is valid.
      const useropHash = getUserOperationHash({
        chainId: chain.chainId,
        entryPointAddress: chain.entryPoint,
        entryPointVersion: '0.7',
        userOperation: userOp as never,
      });

      // Per-(tenant, chain) policy: tenant jsonb overrides merged over the chain's defaults.
      const decision = evaluatePolicy(
        {
          sender: rpcOp.sender,
          callData: rpcOp.callData,
          callGasLimit: userOp.callGasLimit,
          verificationGasLimit: userOp.verificationGasLimit,
          preVerificationGas: userOp.preVerificationGas,
          maxFeePerGas: userOp.maxFeePerGas,
          maxPriorityFeePerGas: userOp.maxPriorityFeePerGas,
          paymaster: rpcOp.paymaster,
          paymasterData: rpcOp.paymasterData,
        },
        session.walletAddress,
        tenantPolicy(caller),
      );

      if (!decision.allowed) {
        // Audit-log the rejection; a conflict here means the hash already has a row
        // (someone else's or an earlier attempt) — never leak that, just reject.
        await db
          .insert(useropLog)
          .values({
            useropHash,
            chainId: chain.chainId,
            sender: rpcOp.sender,
            tenantId: session.tenantId,
            userId: session.userId,
            sessionId: session.sessionId,
            status: 'rejected',
            policyResults: decision.results,
            rejectReason: decision.rejectReason,
          })
          .onConflictDoNothing({ target: useropLog.useropHash });
        log.warn({ useropHash, chainId: chain.chainId, reason: decision.rejectReason }, 'userop rejected by policy');
        for (const rule of decision.results.filter((r) => !r.passed)) {
          metrics.policyRejections.inc({ rule: rule.rule, tenant: tenantSlug, chain: chainLabel });
        }
        metrics.useropRelayed.inc({ status: 'rejected', tenant: tenantSlug, chain: chainLabel });
        return { kind: 'rejected', reason: decision.rejectReason!, policy: decision.results };
      }

      // R-06's linkage: one join from "we relayed this" to "why was it sponsored, and what was
      // it charged". Matched on the operation hash, which the sponsorship service records against
      // its own decision at authorisation time.
      const sponsorshipDecisionId = rpcOp.paymaster
        ? (
            await db
              .select({ id: sponsorshipDecisions.id })
              .from(sponsorshipDecisions)
              .where(and(eq(sponsorshipDecisions.useropHash, useropHash), eq(sponsorshipDecisions.tenantId, session.tenantId)))
              .limit(1)
          )[0]?.id
        : undefined;

      const inserted = await db
        .insert(useropLog)
        .values({
          useropHash,
          chainId: chain.chainId,
          sender: rpcOp.sender,
          tenantId: session.tenantId,
          userId: session.userId,
          sessionId: session.sessionId,
          status: 'accepted',
          policyResults: decision.results,
          rejectReason: decision.rejectReason,
          sponsorshipDecisionId,
        })
        .onConflictDoNothing({ target: useropLog.useropHash })
        .returning({ id: useropLog.id });

      if (inserted.length === 0) {
        const existing = await db.query.useropLog.findFirst({ where: eq(useropLog.useropHash, useropHash) });
        // Idempotent `duplicate: true` is confirmation the op was submitted — only the
        // submitter's own tenant AND user may learn that (V9). Anyone else gets the
        // generic conflict.
        const ownDuplicate = existing && existing.tenantId === session.tenantId && existing.userId === session.userId;
        if (ownDuplicate && (existing.status === 'submitted' || existing.status === 'accepted')) {
          return { kind: 'submitted', userOperationHash: useropHash, duplicate: true };
        }
        return { kind: 'conflict' };
      }

      try {
        // Submitted to the submission endpoint configured for the RESOLVED chain, and to
        // no other (MC-58).
        const bundlerHash = await chain.bundler.sendUserOperation(rpcOp as unknown as Record<string, unknown>);
        if (bundlerHash.toLowerCase() !== useropHash.toLowerCase()) {
          log.warn({ useropHash, bundlerHash, chainId: chain.chainId }, 'bundler returned a different userop hash than computed');
        }
        await db
          .update(useropLog)
          .set({ status: 'submitted', bundlerResponse: { bundlerHash } })
          .where(eq(useropLog.id, inserted[0].id));
        metrics.useropRelayed.inc({ status: 'submitted', tenant: tenantSlug, chain: chainLabel });
        // the server-computed hash is the canonical id (log key, status endpoint, idempotency)
        return { kind: 'submitted', userOperationHash: useropHash };
      } catch (error) {
        await db
          .update(useropLog)
          .set({ status: 'failed', bundlerResponse: { error: (error as Error).message } })
          .where(eq(useropLog.id, inserted[0].id));
        metrics.useropRelayed.inc({ status: 'failed', tenant: tenantSlug, chain: chainLabel });
        throw error;
      }
    } finally {
      // rejected and failed ops observe the histogram too (was success-path only)
      stopTimer({ tenant: tenantSlug, chain: chainLabel });
    }
  };

  return { tenantPolicy, takeRelaySlot, relay };
}

export type UseropRelay = ReturnType<typeof createUseropRelay>;
