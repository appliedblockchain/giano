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
import type { BundlerService } from '../services/bundler.js';
import { mergePolicy } from '../services/tenants.js';
import type { PolicyConfig } from '../services/userop-policy.js';
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
  opts: { db: Db; config: AppConfig; bundler: BundlerService; defaultPolicy: PolicyConfig },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  // request.tenant is backfilled from the session by requireSession, so no tenant
  // service is needed here — the merged policy reads straight off the request.
  const { db, config, bundler, defaultPolicy } = opts;

  const tenantPolicy = (request: FastifyRequest) => ({
    ...mergePolicy(defaultPolicy, request.tenant?.policy),
    // The 16-byte id the paymaster bills, so `sponsored-tenant-match` can cross-check a sponsored
    // operation against the session that submitted it.
    ...(request.session ? { sponsorshipTenantId: `0x${request.session.tenantId.replace(/-/g, '')}` as `0x${string}` } : {}),
  });

  /**
   * Light per-tenant relay limit (G5.2): a shared bundler and executor balance mean one
   * tenant must not be able to exhaust them for everyone. Hand-rolled fixed window
   * (in-memory, single-process — acceptable for this iteration) rather than
   * @fastify/rate-limit, because it must run AFTER requireSession resolved the tenant.
   */
  const relayWindows = new Map<string, { windowStart: number; count: number }>();
  const relayLimit = async (request: FastifyRequest, reply: FastifyReply) => {
    const session = request.session;
    if (!session) return; // requireSession already replied
    const max = tenantPolicy(request).relayRateLimitPerMinute ?? config.USEROP_RATE_LIMIT_PER_MINUTE;
    const now = Date.now();
    const window = relayWindows.get(session.tenantId);
    if (!window || now - window.windowStart >= 60_000) {
      relayWindows.set(session.tenantId, { windowStart: now, count: 1 });
      return;
    }
    window.count += 1;
    if (window.count > max) {
      app.metrics.useropRelayed.inc({ status: 'rate-limited', tenant: request.tenant?.slug ?? 'unknown' });
      return reply.code(429).send({ error: 'rate-limited', message: `tenant relay limit of ${max}/minute exceeded` });
    }
  };

  app.post(
    '/v1/userops',
    {
      preHandler: [app.requireSession, relayLimit],
      schema: {
        tags: ['userops'],
        security: [{ session: [] }],
        body: z.object({ userOperation: rpcUserOpSchema }),
        response: {
          200: z.object({ userOperationHash: z.string(), duplicate: z.boolean().optional() }),
          403: z.object({ error: z.string(), message: z.string(), policy: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })) }),
          429: z.object({ error: z.string(), message: z.string() }),
        },
      },
    },
    async (request, reply) => {
      const stopTimer = app.metrics.useropLatency.startTimer();
      const session = request.session!;
      const tenantSlug = request.tenant?.slug ?? 'unknown';
      try {
        const rpcOp = request.body.userOperation;
        const userOp = toBigIntUserOp(rpcOp);

        // Hash is computed server-side against the SERVER's EntryPoint and chain — the
        // request cannot influence where this op is valid.
        const useropHash = getUserOperationHash({
          chainId: config.CHAIN_ID,
          entryPointAddress: bundler.entryPoint,
          entryPointVersion: '0.7',
          userOperation: userOp as never,
        });

        // Per-tenant policy: tenant jsonb overrides merged over the deployment defaults.
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
          tenantPolicy(request),
        );

        if (!decision.allowed) {
          // Audit-log the rejection; a conflict here means the hash already has a row
          // (someone else's or an earlier attempt) — never leak that, just reject.
          await db
            .insert(useropLog)
            .values({
              useropHash,
              sender: rpcOp.sender,
              tenantId: session.tenantId,
              userId: session.userId,
              sessionId: session.sessionId,
              status: 'rejected',
              policyResults: decision.results,
              rejectReason: decision.rejectReason,
            })
            .onConflictDoNothing({ target: useropLog.useropHash });
          request.log.warn({ useropHash, reason: decision.rejectReason }, 'userop rejected by policy');
          for (const rule of decision.results.filter((r) => !r.passed)) {
            app.metrics.policyRejections.inc({ rule: rule.rule, tenant: tenantSlug });
          }
          app.metrics.useropRelayed.inc({ status: 'rejected', tenant: tenantSlug });
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
          const bundlerHash = await bundler.sendUserOperation(rpcOp as unknown as Record<string, unknown>);
          if (bundlerHash.toLowerCase() !== useropHash.toLowerCase()) {
            request.log.warn({ useropHash, bundlerHash }, 'bundler returned a different userop hash than computed');
          }
          await db
            .update(useropLog)
            .set({ status: 'submitted', bundlerResponse: { bundlerHash } })
            .where(eq(useropLog.id, inserted[0].id));
          app.metrics.useropRelayed.inc({ status: 'submitted', tenant: tenantSlug });
          // the server-computed hash is the canonical id (log key, status endpoint, idempotency)
          return { userOperationHash: useropHash };
        } catch (error) {
          await db
            .update(useropLog)
            .set({ status: 'failed', bundlerResponse: { error: (error as Error).message } })
            .where(eq(useropLog.id, inserted[0].id));
          app.metrics.useropRelayed.inc({ status: 'failed', tenant: tenantSlug });
          throw error;
        }
      } finally {
        // rejected and failed ops observe the histogram too (was success-path only)
        stopTimer({ tenant: tenantSlug });
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
      const receipt = await bundler.getUserOperationReceipt(request.params.hash);
      return { receipt };
    },
  );
}
