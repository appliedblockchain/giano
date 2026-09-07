import { and, eq } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { Address, Hex } from 'viem';
import { getUserOperationHash } from 'viem/account-abstraction';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import { sponsorshipDecisions, useropLog } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { ChainRegistry, ChainServices } from '../services/chains.js';
import { mergePolicy } from '../services/tenants.js';
import { evaluatePolicy } from '../services/userop-policy.js';

const hexData = z.string().regex(/^0x[0-9a-fA-F]*$/) as z.ZodType<Hex>;
const hexQuantity = z.string().regex(/^0x[0-9a-fA-F]+$/) as z.ZodType<Hex>;
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/) as z.ZodType<Address>;

/**
 * EntryPoint v0.7 user operation in JSON-RPC (hex) encoding. The EntryPoint address
 * is NEVER taken from the request — the server submits against its configured one.
 * (The old demo trusted `signedUserOp.account.entryPoint.address` — that hole is closed.)
 */
const rpcUserOpSchema = z
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

type RpcUserOp = z.infer<typeof rpcUserOpSchema>;

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

export default async function useropRoutes(
  instance: FastifyInstance,
  opts: {
    db: Db;
    config: AppConfig;
    registry: ChainRegistry;
    /** Deployment-wide numeric caps. Address-valued defaults live on each chain descriptor (MC-61). */
    defaultPolicy: { maxCallGas: bigint; maxVerificationGas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint };
  },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  // request.tenant is backfilled from the session by requireSession, so no tenant
  // service is needed here — the merged policy reads straight off the request.
  const { db, config, registry, defaultPolicy } = opts;

  /**
   * Policy for one (tenant, chain), per §9.5: env caps ← the chain descriptor's own policy
   * ← the tenant's overrides for THAT chain. Address-valued fields never cross chains.
   */
  const tenantPolicy = (request: FastifyRequest, chain: ChainServices) => {
    const chainDefaults = {
      maxCallGas: chain.descriptor.policy.maxCallGas ?? defaultPolicy.maxCallGas,
      maxVerificationGas: chain.descriptor.policy.maxVerificationGas ?? defaultPolicy.maxVerificationGas,
      maxFeePerGas: chain.descriptor.policy.maxFeePerGas ?? defaultPolicy.maxFeePerGas,
      maxPriorityFeePerGas: chain.descriptor.policy.maxPriorityFeePerGas ?? defaultPolicy.maxPriorityFeePerGas,
      allowedTargets: chain.descriptor.policy.allowedTargets,
      allowedPaymasters: chain.descriptor.policy.allowedPaymasters,
    };
    return {
      ...mergePolicy(chainDefaults, request.tenant?.policy, chain.chainId),
      // The 16-byte id the paymaster bills, so `sponsored-tenant-match` can cross-check a sponsored
      // operation against the session that submitted it.
      ...(request.session ? { sponsorshipTenantId: `0x${request.session.tenantId.replace(/-/g, '')}` as `0x${string}` } : {}),
    };
  };

  /**
   * Light per-tenant relay limit (G5.2): a shared bundler and executor balance mean one
   * tenant must not be able to exhaust them for everyone. Hand-rolled fixed window
   * (in-memory, single-process — acceptable for this iteration) rather than
   * @fastify/rate-limit, because it must run AFTER requireSession resolved the tenant.
   */
  // One window per tenant, SHARED across chains (MC-63): adding a chain must not raise a
  // tenant's effective ceiling — the limit protects the relay and the tenant's own spend,
  // neither of which became N times more available when the deployment gained chains.
  const relayWindows = new Map<string, { windowStart: number; count: number }>();
  const relayLimit = async (request: FastifyRequest, reply: FastifyReply) => {
    const session = request.session;
    if (!session || !request.chain) return; // requireSession/requireChain already replied
    const max = tenantPolicy(request, request.chain).relayRateLimitPerMinute ?? config.USEROP_RATE_LIMIT_PER_MINUTE;
    const now = Date.now();
    const window = relayWindows.get(session.tenantId);
    if (!window || now - window.windowStart >= 60_000) {
      relayWindows.set(session.tenantId, { windowStart: now, count: 1 });
      return;
    }
    window.count += 1;
    if (window.count > max) {
      app.metrics.useropRelayed.inc({ status: 'rate-limited', tenant: request.tenant?.slug ?? 'unknown', chain: String(request.chain.chainId) });
      return reply.code(429).send({ error: 'rate-limited', message: `tenant relay limit of ${max}/minute exceeded` });
    }
  };

  app.post(
    '/v1/userops',
    {
      // requireChain BEFORE the rate limit: an unserved chain is refused without consuming
      // any of the tenant's window.
      preHandler: [app.requireSession, app.requireChain, relayLimit],
      schema: {
        tags: ['userops'],
        security: [{ session: [] }],
        body: z.object({
          userOperation: rpcUserOpSchema,
          /**
           * The chain to submit to. Required when the deployment serves several chains;
           * optional when it serves one, where it must then match (MC-53). Validated against
           * the closed configured registry before any work happens (MC-51, MC-52).
           */
          chainId: z.number().int().positive().optional(),
        }),
        response: {
          200: z.object({ userOperationHash: z.string(), duplicate: z.boolean().optional() }),
          400: z.object({ error: z.string(), message: z.string(), servedChainIds: z.array(z.number()).optional() }),
          403: z.object({ error: z.string(), message: z.string(), policy: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })) }),
          429: z.object({ error: z.string(), message: z.string() }),
          503: z.object({ error: z.string(), message: z.string() }),
        },
      },
    },
    async (request, reply) => {
      const stopTimer = app.metrics.useropLatency.startTimer();
      const session = request.session!;
      const chain = request.chain!;
      const chainLabel = String(chain.chainId);
      const tenantSlug = request.tenant?.slug ?? 'unknown';
      try {
        const rpcOp = request.body.userOperation;
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
          tenantPolicy(request, chain),
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
          request.log.warn({ useropHash, chainId: chain.chainId, reason: decision.rejectReason }, 'userop rejected by policy');
          for (const rule of decision.results.filter((r) => !r.passed)) {
            app.metrics.policyRejections.inc({ rule: rule.rule, tenant: tenantSlug, chain: chainLabel });
          }
          app.metrics.useropRelayed.inc({ status: 'rejected', tenant: tenantSlug, chain: chainLabel });
          return reply.code(403).send({ error: 'policy-rejected', message: decision.rejectReason!, policy: decision.results });
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
            return { userOperationHash: useropHash, duplicate: true };
          }
          throw new ApiError(409, 'duplicate', 'user operation was already submitted');
        }

        try {
          // Submitted to the submission endpoint configured for the RESOLVED chain, and to
          // no other (MC-58).
          const bundlerHash = await chain.bundler.sendUserOperation(rpcOp as unknown as Record<string, unknown>);
          if (bundlerHash.toLowerCase() !== useropHash.toLowerCase()) {
            request.log.warn({ useropHash, bundlerHash, chainId: chain.chainId }, 'bundler returned a different userop hash than computed');
          }
          await db
            .update(useropLog)
            .set({ status: 'submitted', bundlerResponse: { bundlerHash } })
            .where(eq(useropLog.id, inserted[0].id));
          app.metrics.useropRelayed.inc({ status: 'submitted', tenant: tenantSlug, chain: chainLabel });
          // the server-computed hash is the canonical id (log key, status endpoint, idempotency)
          return { userOperationHash: useropHash };
        } catch (error) {
          await db
            .update(useropLog)
            .set({ status: 'failed', bundlerResponse: { error: (error as Error).message } })
            .where(eq(useropLog.id, inserted[0].id));
          app.metrics.useropRelayed.inc({ status: 'failed', tenant: tenantSlug, chain: chainLabel });
          throw error;
        }
      } finally {
        // rejected and failed ops observe the histogram too (was success-path only)
        stopTimer({ tenant: tenantSlug, chain: chainLabel });
      }
    },
  );

  app.get(
    '/v1/userops/:hash',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['userops'],
        security: [{ session: [] }],
        params: z.object({ hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }),
        response: {
          200: z.object({
            userOperationHash: z.string(),
            chainId: z.number(),
            sender: z.string(),
            status: z.enum(['accepted', 'rejected', 'submitted', 'failed']),
            policyResults: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })),
            rejectReason: z.string().nullable(),
            createdAt: z.string(),
          }),
        },
      },
    },
    async (request) => {
      const row = await db.query.useropLog.findFirst({ where: eq(useropLog.useropHash, request.params.hash) });
      if (!row || row.userId !== request.session!.userId || row.tenantId !== request.session!.tenantId) {
        throw new ApiError(404, 'not-found', 'user operation not found');
      }
      return {
        userOperationHash: row.useropHash,
        chainId: row.chainId,
        sender: row.sender,
        status: row.status,
        policyResults: row.policyResults as never,
        rejectReason: row.rejectReason,
        createdAt: row.createdAt.toISOString(),
      };
    },
  );

  /**
   * Public, read-only receipt lookup (on-chain public data). Deliberately tenant-free
   * and unauthenticated (D3.7): the receipt is public chain state, and thin-SDK dApps
   * await inclusion here without ever needing a bundler URL of their own (P3.4).
   */
  app.get(
    '/v1/userops/:hash/receipt',
    {
      schema: {
        tags: ['userops'],
        params: z.object({ hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }),
        response: { 200: z.object({ receipt: z.unknown().nullable() }) },
      },
    },
    async (request) => {
      // No chainId parameter: the operation hash commits to the chain, and userop_log now
      // records it (MC-59) — so the chain is resolved from the logged row and the SDK's
      // receipt polling keeps working untouched (§9.3). An op this deployment never relayed
      // falls back to the sole chain when one is configured, and is unknown otherwise.
      const row = await db.query.useropLog.findFirst({ where: eq(useropLog.useropHash, request.params.hash) });
      const chain = (row && registry.tryGet(row.chainId)) || (registry.size === 1 ? registry.sole : undefined);
      if (!chain) return { receipt: null };
      const receipt = await chain.bundler.getUserOperationReceipt(request.params.hash);
      return { receipt };
    },
  );
}
