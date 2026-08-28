import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import type { Address, Hex } from 'viem';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { ChainRegistry } from '../services/chains.js';
import { packUints, type SponsorshipMethod } from '../services/sponsorship-service.js';
import type { SponsorshipRefusalReason, SponsorshipRuleResult } from '../services/sponsorship-rules.js';

/**
 * The ERC-7677 sponsorship service.
 *
 * One route speaking JSON-RPC 2.0, reached the same way everything else is — through the tenant's
 * own edge, same-origin under `/api` — so standard wallet tooling can point at
 * `https://wallet.tenant.example/api/v1/paymaster` and a tenant running its own interface needs no
 * Giano-specific integration work.
 */

const hexData = z.string().regex(/^0x[0-9a-fA-F]*$/) as z.ZodType<Hex>;
const hexQuantity = z.string().regex(/^0x[0-9a-fA-F]+$/) as z.ZodType<Hex>;
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/) as z.ZodType<Address>;

/**
 * The operation as a wallet hands it to a paymaster service. Gas fields are optional because
 * `pm_getPaymasterStubData` is called *during* estimation, before some of them are known.
 */
const candidateOpSchema = z
  .object({
    sender: address,
    nonce: hexQuantity,
    callData: hexData,
    callGasLimit: hexQuantity.optional(),
    verificationGasLimit: hexQuantity.optional(),
    preVerificationGas: hexQuantity.optional(),
    maxFeePerGas: hexQuantity.optional(),
    maxPriorityFeePerGas: hexQuantity.optional(),
    factory: address.optional(),
    factoryData: hexData.optional(),
    paymaster: address.optional(),
    paymasterVerificationGasLimit: hexQuantity.optional(),
    paymasterPostOpGasLimit: hexQuantity.optional(),
    paymasterData: hexData.optional(),
    signature: hexData.optional(),
  })
  .strip();

const jsonRpcRequestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]),
  method: z.enum(['pm_getPaymasterStubData', 'pm_getPaymasterData']),
  /** `[userOp, entryPoint, chainId, context]` — the ERC-7677 parameter shape. */
  params: z.tuple([candidateOpSchema, address, hexQuantity]).rest(z.unknown()),
});

/**
 * Accepted and ignored in v1, except for an optional pre-flight hint. Unknown keys are rejected
 * rather than silently dropped, so a tenant cannot come to depend on a field we do not honour.
 */
const contextSchema = z.object({ preflight: z.boolean().optional() }).strict().optional();

/**
 * §5.4 of the specification. The wallet keys its behaviour off these, never off the message.
 *
 * Two of them are not rule outcomes and so are not in the engine's own reason union:
 * `chain-or-entrypoint-mismatch` is settled before the rules run, and `temporarily-unavailable`
 * is deliberately separate from every rule refusal so that an outage cannot be mistaken for a
 * misconfiguration.
 */
type RefusalReason = SponsorshipRefusalReason | 'temporarily-unavailable' | 'chain-or-entrypoint-mismatch';

const REASON_CODES: Record<RefusalReason, number> = {
  'sponsorship-disabled': -32001,
  'no-sponsorship-config': -32002,
  'contract-not-allowed': -32003,
  'function-not-allowed': -32004,
  'wallet-management-not-sponsored': -32005,
  'cost-exceeds-cap': -32006,
  'insufficient-balance': -32007,
  'tenant-in-deficit': -32008,
  'not-your-wallet': -32009,
  'chain-or-entrypoint-mismatch': -32010,
  'temporarily-unavailable': -32011,
};

const JSON_RPC_INVALID_PARAMS = -32602;

/**
 * When gas limits are absent — which they are during estimation — the service has to assume
 * something to evaluate the cost cap and the balance at all. Assuming *generously* is the only
 * safe direction: a stub that under-assumed would tell the user their transaction is sponsorable
 * and then refuse it at signing time, after they had already approved.
 */
const ESTIMATION_DEFAULTS = {
  callGasLimit: 1_000_000n,
  verificationGasLimit: 1_000_000n,
  preVerificationGas: 100_000n,
  paymasterVerificationGasLimit: 150_000n,
  paymasterPostOpGasLimit: 100_000n,
} as const;

export default async function paymasterRoutes(
  instance: FastifyInstance,
  opts: { config: AppConfig; registry: ChainRegistry },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  const { config, registry } = opts;

  /**
   * Per-tenant limit with its own budget, separate from the relay's: pre-flight traffic is
   * legitimate and frequent, and it must not be usable to hammer the signer.
   */
  const windows = new Map<string, { windowStart: number; count: number }>();
  const rateLimit = async (request: FastifyRequest, reply: FastifyReply) => {
    const session = request.session;
    if (!session) return;
    const limit = config.SPONSORSHIP_RATE_LIMIT_PER_MINUTE;
    const key = session.tenantId;
    const nowMs = Date.now();
    const entry = windows.get(key);
    if (!entry || nowMs - entry.windowStart >= 60_000) {
      windows.set(key, { windowStart: nowMs, count: 1 });
      return;
    }
    entry.count += 1;
    if (entry.count > limit) {
      return reply.code(429).send({ error: 'rate-limited', message: `sponsorship rate limit of ${limit}/minute exceeded` });
    }
  };

  app.post(
    '/v1/paymaster',
    {
      preHandler: [app.requireSession, rateLimit],
      schema: {
        tags: ['paymaster'],
        summary: 'ERC-7677 paymaster service (pm_getPaymasterStubData, pm_getPaymasterData)',
        description:
          'Decides whether to sponsor a user operation for the session\'s tenant, and if so issues an ' +
          'authorisation the paymaster contract verifies on-chain. Refusals carry a stable machine-readable ' +
          'reason in `error.data.reason`.',
        security: [{ session: [] }],
        body: jsonRpcRequestSchema,
        response: {
          200: z.object({
            jsonrpc: z.literal('2.0'),
            id: z.union([z.string(), z.number(), z.null()]),
            result: z
              .object({
                paymaster: address,
                paymasterData: hexData,
                paymasterVerificationGasLimit: hexQuantity,
                paymasterPostOpGasLimit: hexQuantity,
              })
              .optional(),
            error: z
              .object({
                code: z.number(),
                message: z.string(),
                data: z
                  .object({
                    reason: z.string(),
                    retryable: z.boolean(),
                    ruleResults: z.array(z.object({ rule: z.string(), passed: z.boolean(), detail: z.string().optional() })),
                  })
                  .optional(),
              })
              .optional(),
          }),
        },
      },
    },
    async (request) => {
      const session = request.session!;
      const { id, method, params } = request.body;
      const [op, entryPoint, chainIdHex, rawContext] = params as [
        z.infer<typeof candidateOpSchema>,
        Address,
        Hex,
        unknown,
      ];

      const rpcError = (code: number, message: string, reason?: RefusalReason, ruleResults: SponsorshipRuleResult[] = []) => ({
        jsonrpc: '2.0' as const,
        id,
        error: {
          code,
          message,
          ...(reason ? { data: { reason, retryable: reason === 'temporarily-unavailable', ruleResults } } : {}),
        },
      });

      // R-14, §10.1. ERC-7677 already puts the chain on the wire (params[2]); the service now
      // ROUTES on it instead of rejecting all but one. The chain and the EntryPoint are still
      // validated against server configuration, never trusted from the request — this only
      // widens what "server configuration" contains (MC-70).
      const chain = registry.tryGet(Number(BigInt(chainIdHex)));
      if (!chain) {
        return rpcError(
          REASON_CODES['chain-or-entrypoint-mismatch'],
          `this service does not sponsor operations on chain ${Number(BigInt(chainIdHex))}`,
          'chain-or-entrypoint-mismatch',
        );
      }
      if (chain.status !== 'ready') {
        // Retryable, and distinct from the permanent refusal above (MC-55).
        return rpcError(REASON_CODES['temporarily-unavailable'], `chain ${chain.chainId} is temporarily unavailable`, 'temporarily-unavailable');
      }
      if (entryPoint.toLowerCase() !== chain.entryPoint.toLowerCase()) {
        return rpcError(
          REASON_CODES['chain-or-entrypoint-mismatch'],
          `this service sponsors operations for EntryPoint ${chain.entryPoint} on chain ${chain.chainId}`,
          'chain-or-entrypoint-mismatch',
        );
      }
      // Sponsorship may be enabled per chain (MC-65): a chain with no paymaster sponsors nothing.
      const sponsorship = chain.sponsorship;
      if (!sponsorship) {
        return rpcError(
          REASON_CODES['sponsorship-disabled'],
          `gas sponsorship is not enabled on chain ${chain.chainId}`,
          'sponsorship-disabled',
        );
      }

      const context = contextSchema.safeParse(rawContext ?? undefined);
      if (!context.success) {
        return rpcError(
          JSON_RPC_INVALID_PARAMS,
          `unsupported context keys: ${context.error.issues.map((i) => i.path.join('.')).join(', ')}`,
        );
      }

      // R-13, checked here as well as inside the rules engine. The engine's version is what lands
      // in the audit trail; this one keeps a foreign sender from reaching the ledger at all.
      if (op.sender.toLowerCase() !== session.walletAddress.toLowerCase()) {
        request.log.warn(
          { alert: 'sponsorship-foreign-sender', sender: op.sender, sessionWallet: session.walletAddress },
          'sponsorship requested for a wallet the session does not own',
        );
        return rpcError(REASON_CODES['not-your-wallet'], 'sponsorship is only issued for the session\'s own wallet', 'not-your-wallet');
      }

      const quantity = (value: Hex | undefined, fallback: bigint) => (value === undefined ? fallback : BigInt(value));

      const callGasLimit = quantity(op.callGasLimit, ESTIMATION_DEFAULTS.callGasLimit);
      const verificationGasLimit = quantity(op.verificationGasLimit, ESTIMATION_DEFAULTS.verificationGasLimit);
      const preVerificationGas = quantity(op.preVerificationGas, ESTIMATION_DEFAULTS.preVerificationGas);
      const maxFeePerGas = quantity(op.maxFeePerGas, 0n);
      const maxPriorityFeePerGas = quantity(op.maxPriorityFeePerGas, maxFeePerGas);
      const paymasterVerificationGasLimit = quantity(
        op.paymasterVerificationGasLimit,
        ESTIMATION_DEFAULTS.paymasterVerificationGasLimit,
      );
      const paymasterPostOpGasLimit = quantity(op.paymasterPostOpGasLimit, ESTIMATION_DEFAULTS.paymasterPostOpGasLimit);

      // A zero fee would make every cost check pass trivially and every reservation zero, so it is
      // refused rather than defaulted: the wallet is expected to estimate fees from the chain.
      if (maxFeePerGas === 0n && method === 'pm_getPaymasterData') {
        return rpcError(JSON_RPC_INVALID_PARAMS, 'maxFeePerGas is required to authorise sponsorship');
      }

      const outcome = await sponsorship.decide({
        method: (method === 'pm_getPaymasterStubData' ? 'stub' : 'data') satisfies SponsorshipMethod,
        session,
        nonce: BigInt(op.nonce),
        accountGasLimits: packUints(verificationGasLimit, callGasLimit),
        gasFees: packUints(maxPriorityFeePerGas, maxFeePerGas),
        candidate: {
          sender: op.sender,
          callData: op.callData,
          callGasLimit,
          verificationGasLimit,
          preVerificationGas,
          maxFeePerGas,
          paymasterVerificationGasLimit,
          paymasterPostOpGasLimit,
          ...(op.factory ? { factory: op.factory, factoryData: op.factoryData ?? '0x' } : {}),
        },
      });

      if (outcome.outcome === 'refused') {
        request.log.info(
          { sponsorship: 'refused', reason: outcome.reason, method, decisionId: outcome.decisionId },
          'sponsorship refused',
        );
        return rpcError(REASON_CODES[outcome.reason], outcome.message, outcome.reason, outcome.ruleResults);
      }

      return {
        jsonrpc: '2.0' as const,
        id,
        result: {
          paymaster: outcome.paymaster,
          paymasterData: outcome.paymasterData,
          paymasterVerificationGasLimit: `0x${outcome.paymasterVerificationGasLimit.toString(16)}` as Hex,
          paymasterPostOpGasLimit: `0x${outcome.paymasterPostOpGasLimit.toString(16)}` as Hex,
        },
      };
    },
  );
}
