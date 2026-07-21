import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { Address, Hex } from 'viem';
import { getUserOperationHash } from 'viem/account-abstraction';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import { useropLog } from '../db/schema.js';
import { ApiError } from '../plugins/error-handler.js';
import type { BundlerService } from '../services/bundler.js';
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
  opts: { db: Db; config: AppConfig; bundler: BundlerService; policy: PolicyConfig },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { db, config, bundler, policy } = opts;

  app.post(
    '/v1/userops',
    {
      preHandler: app.requireSession,
      schema: {
        tags: ['userops'],
        security: [{ session: [] }],
        body: z.object({ userOperation: rpcUserOpSchema }),
        response: {
          200: z.object({ userOperationHash: z.string(), duplicate: z.boolean().optional() }),
          403: z.object({ error: z.string(), message: z.string(), policy: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })) }),
        },
      },
    },
    async (request, reply) => {
      const session = request.session!;
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
        },
        session.walletAddress,
        policy,
      );

      const inserted = await db
        .insert(useropLog)
        .values({
          useropHash,
          sender: rpcOp.sender,
          userId: session.userId,
          sessionId: session.sessionId,
          status: decision.allowed ? 'accepted' : 'rejected',
          policyResults: decision.results,
          rejectReason: decision.rejectReason,
        })
        .onConflictDoNothing({ target: useropLog.useropHash })
        .returning({ id: useropLog.id });

      if (inserted.length === 0) {
        // duplicate submission — idempotent answer for already-submitted ops
        const existing = await db.query.useropLog.findFirst({ where: eq(useropLog.useropHash, useropHash) });
        if (existing && (existing.status === 'submitted' || existing.status === 'accepted')) {
          return { userOperationHash: useropHash, duplicate: true };
        }
        throw new ApiError(409, 'duplicate', 'user operation was already submitted and rejected/failed');
      }

      if (!decision.allowed) {
        request.log.warn({ useropHash, reason: decision.rejectReason }, 'userop rejected by policy');
        return reply.code(403).send({ error: 'policy-rejected', message: decision.rejectReason!, policy: decision.results });
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
        // the server-computed hash is the canonical id (log key, status endpoint, idempotency)
        return { userOperationHash: useropHash };
      } catch (error) {
        await db
          .update(useropLog)
          .set({ status: 'failed', bundlerResponse: { error: (error as Error).message } })
          .where(eq(useropLog.id, inserted[0].id));
        throw error;
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
      if (!row || row.userId !== request.session!.userId) {
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
   * Public, read-only receipt lookup (on-chain public data). Exists so thin-SDK dApps
   * can await inclusion without ever needing a bundler URL of their own (P3.4).
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
