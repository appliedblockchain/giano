import { and, desc, eq, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import type { Db } from '../db/index.js';
import {
  sponsorshipDecisions,
  sponsorshipSettlements,
  tenantSponsorship,
  tenantSponsorshipHistory,
} from '../db/schema.js';
import { sha256hex } from '../services/tenants.js';
import type { ChainRegistry } from '../services/chains.js';
import { tenantIdToBytes16, type PaymasterReader } from '../services/paymaster-contract.js';
import { checkWalletManagementCap, formatConfigIssues, sponsorshipConfigSchema } from '../services/sponsorship-config.js';
import type { LedgerService } from '../services/sponsorship-ledger.js';

/**
 * A tenant's own view of its sponsorship: the rules it controls, and the position it needs to be
 * able to reconcile against the chain.
 *
 * Two things are deliberately absent from this surface. **Balance** is not writable here because
 * it moves only through on-chain funding and spending — a tenant that could edit its balance
 * would be editing Giano's books rather than its own money. And the **fee** is not writable here
 * because it is Giano's to set; a tenant that could set its own fee would have no fee.
 *
 * Everything readable here is derived from chain events and carries the block height it was
 * computed at, so a tenant can reproduce the numbers independently rather than trusting our books.
 */
export default async function adminSponsorshipRoutes(
  instance: FastifyInstance,
  opts: { db: Db; config: AppConfig; ledger: LedgerService; registry: ChainRegistry },
) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  // requireChain runs after requireAdmin: with one chain configured the parameter is
  // supplied automatically, so an on-premises tenant never encounters the dimension (MC-53);
  // with several it is required, because a tenant's rules, balance and history are all
  // per chain (MC-66) and guessing which one was meant is exactly what MC-53 forbids.
  app.addHook('preHandler', app.requireAdmin);
  app.addHook('preHandler', app.requireChain);

  const { db, config, ledger } = opts;
  const walletManagementCapWei = config.SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI;

  const wei = z.string();
  const errorBody = z.object({ error: z.string(), message: z.string() });
  /** Selects the chain when several are served; supplied automatically when one is (MC-53). */
  const chainQuery = z.object({ chainId: z.coerce.number().int().positive().optional() });

  const keyHashOf = (request: { headers: { authorization?: string } }) => {
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ')) return null;
    return sha256hex(header.slice('Bearer '.length).trim());
  };

  /** Writes the new configuration and appends the previous one to the history in one transaction. */
  async function writeConfig(tenantId: string, chainId: number, nextConfig: unknown, keyHash: string | null) {
    await db.transaction(async (tx) => {
      await tx.insert(tenantSponsorshipHistory).values({ tenantId, chainId, config: nextConfig, createdByKeyHash: keyHash });
      await tx
        .insert(tenantSponsorship)
        .values({ tenantId, chainId, config: nextConfig, updatedByKeyHash: keyHash })
        .onConflictDoUpdate({
          target: [tenantSponsorship.tenantId, tenantSponsorship.chainId],
          set: { config: nextConfig, updatedAt: new Date(), updatedByKeyHash: keyHash },
        });
    });
  }

  // ── Rules ──────────────────────────────────────────────────────────────────

  app.get(
    '/v1/admin/sponsorship',
    {
      schema: {
        tags: ['admin'],
        summary: 'Read this tenant\'s sponsorship rules',
        security: [{ adminKey: [] }],
        querystring: chainQuery,
        response: {
          200: z.object({
            configured: z.boolean(),
            config: z.unknown(),
            updatedAt: z.string().nullable(),
            /** True when the stored value no longer validates — which means NO sponsorship, not permissive. */
            valid: z.boolean(),
            issues: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
          }),
        },
      },
    },
    async (request) => {
      const tenant = request.adminTenant!;
      const chainId = request.chain!.chainId;
      const [row] = await db
        .select({ config: tenantSponsorship.config, updatedAt: tenantSponsorship.updatedAt })
        .from(tenantSponsorship)
        .where(and(eq(tenantSponsorship.tenantId, tenant.id), eq(tenantSponsorship.chainId, chainId)));

      if (!row) {
        return { configured: false, config: { enabled: false, allowlist: [] }, updatedAt: null, valid: true };
      }

      const parsed = sponsorshipConfigSchema.safeParse(row.config);
      return {
        configured: true,
        config: row.config,
        updatedAt: row.updatedAt.toISOString(),
        valid: parsed.success,
        ...(parsed.success ? {} : { issues: formatConfigIssues(parsed.error) }),
      };
    },
  );

  app.put(
    '/v1/admin/sponsorship',
    {
      schema: {
        tags: ['admin'],
        summary: 'Replace this tenant\'s sponsorship rules (for one chain)',
        description:
          'Full replace, validated on write. Rejected with per-path messages on any violation, so an invalid ' +
          'rule set is never stored and therefore never interpreted permissively. Rules are per chain and never ' +
          'inherited from another chain (MC-67): enabling a new chain is an explicit act.',
        security: [{ adminKey: [] }],
        querystring: chainQuery,
        body: z.unknown(),
        response: {
          200: z.object({ config: z.unknown(), updatedAt: z.string() }),
          400: z.object({
            error: z.string(),
            message: z.string(),
            issues: z.array(z.object({ path: z.string(), message: z.string() })),
          }),
        },
      },
    },
    async (request, reply) => {
      const tenant = request.adminTenant!;
      const parsed = sponsorshipConfigSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: 'validation',
          message: 'sponsorship configuration is not valid',
          issues: formatConfigIssues(parsed.error),
        });
      }

      // Wallet management is platform-governed, so a tenant may lower its cap and never raise it.
      // Rejected rather than clamped: a tenant that asked for a cap and silently got a different
      // one has no way to discover that.
      const capIssues = checkWalletManagementCap(parsed.data, walletManagementCapWei);
      if (capIssues.length > 0) {
        return reply.code(400).send({
          error: 'validation',
          message: 'sponsorship configuration is not valid',
          issues: capIssues,
        });
      }

      const chain = request.chain!;
      await writeConfig(tenant.id, chain.chainId, parsed.data, keyHashOf(request));

      // The reservation statement joins against this row, so a tenant that has just enabled
      // sponsorship must have one — otherwise its first operation is refused for a reason that
      // looks nothing like "you have not funded a balance yet".
      if (chain.paymaster) {
        await ledger.ensureTenantRow({ tenantId: tenant.id, chainId: chain.chainId, paymasterAddress: chain.paymaster.address });
      }

      request.log.info(
        { sponsorship: 'config-replaced', enabled: parsed.data.enabled, chainId: chain.chainId },
        'sponsorship configuration updated',
      );
      return { config: parsed.data, updatedAt: new Date().toISOString() };
    },
  );

  app.patch(
    '/v1/admin/sponsorship',
    {
      schema: {
        tags: ['admin'],
        summary: 'Update fields of this tenant\'s sponsorship rules (for one chain)',
        description:
          'Shallow field-level merge over the stored configuration, then validated as a whole — so a partial ' +
          'update cannot leave the rule set in a state a full replace would have rejected.',
        security: [{ adminKey: [] }],
        querystring: chainQuery,
        body: z.record(z.unknown()),
        response: {
          200: z.object({ config: z.unknown(), updatedAt: z.string() }),
          400: z.object({
            error: z.string(),
            message: z.string(),
            issues: z.array(z.object({ path: z.string(), message: z.string() })),
          }),
        },
      },
    },
    async (request, reply) => {
      const tenant = request.adminTenant!;
      const chain = request.chain!;
      const chainId = chain.chainId;
      const [row] = await db
        .select({ config: tenantSponsorship.config })
        .from(tenantSponsorship)
        .where(and(eq(tenantSponsorship.tenantId, tenant.id), eq(tenantSponsorship.chainId, chainId)));

      const merged = { ...((row?.config as Record<string, unknown>) ?? {}), ...request.body };
      const parsed = sponsorshipConfigSchema.safeParse(merged);
      if (!parsed.success) {
        return reply.code(400).send({
          error: 'validation',
          message: 'the merged sponsorship configuration is not valid',
          issues: formatConfigIssues(parsed.error),
        });
      }

      const capIssues = checkWalletManagementCap(parsed.data, walletManagementCapWei);
      if (capIssues.length > 0) {
        return reply.code(400).send({
          error: 'validation',
          message: 'the merged sponsorship configuration is not valid',
          issues: capIssues,
        });
      }

      await writeConfig(tenant.id, chainId, parsed.data, keyHashOf(request));
      if (chain.paymaster) {
        await ledger.ensureTenantRow({ tenantId: tenant.id, chainId, paymasterAddress: chain.paymaster.address });
      }
      return { config: parsed.data, updatedAt: new Date().toISOString() };
    },
  );

  app.get(
    '/v1/admin/sponsorship/history',
    {
      schema: {
        tags: ['admin'],
        summary: 'Who changed the sponsorship rules, and when',
        security: [{ adminKey: [] }],
        querystring: chainQuery.extend({ limit: z.coerce.number().int().min(1).max(200).default(50) }),
        response: {
          200: z.object({
            revisions: z.array(
              z.object({
                id: z.string(),
                config: z.unknown(),
                createdAt: z.string(),
                /** The admin key's hash, not the key: enough to tell two writers apart. */
                createdByKeyHash: z.string().nullable(),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const tenant = request.adminTenant!;
      const chainId = request.chain!.chainId;
      const rows = await db
        .select()
        .from(tenantSponsorshipHistory)
        .where(and(eq(tenantSponsorshipHistory.tenantId, tenant.id), eq(tenantSponsorshipHistory.chainId, chainId)))
        .orderBy(desc(tenantSponsorshipHistory.createdAt))
        .limit(request.query.limit);

      return {
        revisions: rows.map((row) => ({
          id: row.id,
          config: row.config,
          createdAt: row.createdAt.toISOString(),
          createdByKeyHash: row.createdByKeyHash,
        })),
      };
    },
  );

  // ── Position ───────────────────────────────────────────────────────────────

  app.get(
    '/v1/admin/sponsorship/balance',
    {
      schema: {
        tags: ['admin'],
        summary: 'This tenant\'s gas balance, reservations and where to fund',
        description:
          'Read live from the paymaster contract, with the block it was read at, so the figures can be ' +
          'reproduced from the chain rather than taken on trust.',
        security: [{ adminKey: [] }],
        querystring: chainQuery,
        response: {
          200: z.object({
            paymasterAddress: z.string(),
            chainId: z.number(),
            registered: z.boolean(),
            enabled: z.boolean(),
            withdrawAddress: z.string().nullable(),
            balanceWei: wei,
            reservedWei: wei,
            availableWei: wei,
            deficitWei: wei,
            feeWei: wei,
            blockNumber: z.string(),
            /** The address to send funding to, and the call that attributes it to this tenant. */
            fundingInstructions: z.object({ to: z.string(), call: z.string(), tenantId: z.string() }),
          }),
          503: errorBody,
        },
      },
    },
    async (request, reply) => {
      const tenant = request.adminTenant!;
      const chain = request.chain!;
      const chainId = chain.chainId;
      const paymaster = chain.paymaster;
      if (!paymaster) {
        return reply.code(503).send({ error: 'sponsorship-disabled', message: `gas sponsorship is not enabled on chain ${chainId}` });
      }

      const tenantId = tenantIdToBytes16(tenant.id);
      let onChain: Awaited<ReturnType<PaymasterReader['tenant']>>;
      let blockNumber: bigint;
      try {
        [onChain, blockNumber] = await Promise.all([paymaster.tenant(tenantId), paymaster.blockNumber()]);
      } catch (error) {
        return reply.code(503).send({ error: 'chain-unreachable', message: (error as Error).message });
      }

      // Reservations are ours; the balance is the chain's. Reading each from its own authority is
      // what keeps "available" honest — a cached balance could be stale, but it is never the
      // number a tenant is told.
      const view = await ledger.getBalanceView(tenant.id, chainId);
      const available = onChain.balanceWei - view.reservedWei;

      return {
        paymasterAddress: paymaster.address,
        chainId,
        registered: onChain.registered,
        enabled: onChain.enabled,
        withdrawAddress: onChain.registered ? onChain.withdrawAddress : null,
        balanceWei: onChain.balanceWei.toString(),
        reservedWei: view.reservedWei.toString(),
        availableWei: (available > 0n ? available : 0n).toString(),
        deficitWei: onChain.deficitWei.toString(),
        feeWei: onChain.feeWei.toString(),
        blockNumber: blockNumber.toString(),
        fundingInstructions: {
          to: paymaster.address,
          call: `depositFor(${tenantId})`,
          tenantId,
        },
      };
    },
  );

  app.get(
    '/v1/admin/sponsorship/spend',
    {
      schema: {
        tags: ['admin'],
        summary: 'What this tenant has been charged, broken down',
        description:
          'One row per settled operation, with gas, Giano\'s fee and the overhead allowance kept separate — ' +
          'each row traceable to a `Sponsored` event on chain.',
        security: [{ adminKey: [] }],
        querystring: chainQuery.extend({
          limit: z.coerce.number().int().min(1).max(500).default(100),
          before: z.string().datetime().optional(),
        }),
        response: {
          200: z.object({
            settlements: z.array(
              z.object({
                useropHash: z.string(),
                sender: z.string(),
                gasCostWei: wei,
                feeWei: wei,
                overheadWei: wei,
                totalWei: wei,
                success: z.boolean(),
                blockNumber: z.string(),
                observedAt: z.string(),
              }),
            ),
            totals: z.object({ gasCostWei: wei, feeWei: wei, overheadWei: wei, totalWei: wei, count: z.number() }),
          }),
        },
      },
    },
    async (request) => {
      const tenant = request.adminTenant!;
      const chainId = request.chain!.chainId;
      const conditions = [eq(sponsorshipSettlements.tenantId, tenant.id), eq(sponsorshipSettlements.chainId, chainId)];
      if (request.query.before) {
        conditions.push(sql`${sponsorshipSettlements.observedAt} < ${new Date(request.query.before)}`);
      }

      const rows = await db
        .select()
        .from(sponsorshipSettlements)
        .where(and(...conditions))
        .orderBy(desc(sponsorshipSettlements.observedAt))
        .limit(request.query.limit);

      // Totals over the tenant's whole history, not just this page: a page total would be a
      // number nobody could reconcile against anything.
      const [totals] = await db
        .select({
          gasCostWei: sql<string>`COALESCE(SUM(${sponsorshipSettlements.gasCostWei}), 0)::text`,
          feeWei: sql<string>`COALESCE(SUM(${sponsorshipSettlements.feeWei}), 0)::text`,
          overheadWei: sql<string>`COALESCE(SUM(${sponsorshipSettlements.overheadWei}), 0)::text`,
          totalWei: sql<string>`COALESCE(SUM(${sponsorshipSettlements.totalWei}), 0)::text`,
          count: sql<number>`COUNT(*)::int`,
        })
        .from(sponsorshipSettlements)
        .where(and(eq(sponsorshipSettlements.tenantId, tenant.id), eq(sponsorshipSettlements.chainId, chainId)));

      return {
        settlements: rows.map((row) => ({
          useropHash: row.useropHash,
          sender: row.sender,
          gasCostWei: row.gasCostWei,
          feeWei: row.feeWei,
          overheadWei: row.overheadWei,
          totalWei: row.totalWei,
          success: row.success,
          blockNumber: row.blockNumber.toString(),
          observedAt: row.observedAt.toISOString(),
        })),
        totals,
      };
    },
  );

  app.get(
    '/v1/admin/sponsorship/decisions',
    {
      schema: {
        tags: ['admin'],
        summary: 'Every sponsorship decision, allowed or refused, with the rule-by-rule results',
        description:
          'Includes the pre-approval checks that never became transactions — those are exactly the decisions a ' +
          'user was shown, so they are what answers "why did my user see a refusal?".',
        security: [{ adminKey: [] }],
        querystring: chainQuery.extend({
          limit: z.coerce.number().int().min(1).max(500).default(100),
          outcome: z.enum(['allowed', 'refused']).optional(),
        }),
        response: {
          200: z.object({
            decisions: z.array(
              z.object({
                id: z.string(),
                method: z.string(),
                sender: z.string(),
                outcome: z.string(),
                reason: z.string().nullable(),
                ruleResults: z.unknown(),
                feeWei: wei.nullable(),
                createdAt: z.string(),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const tenant = request.adminTenant!;
      const chainId = request.chain!.chainId;
      const conditions = [eq(sponsorshipDecisions.tenantId, tenant.id), eq(sponsorshipDecisions.chainId, chainId)];
      if (request.query.outcome) conditions.push(eq(sponsorshipDecisions.outcome, request.query.outcome));

      const rows = await db
        .select()
        .from(sponsorshipDecisions)
        .where(and(...conditions))
        .orderBy(desc(sponsorshipDecisions.createdAt))
        .limit(request.query.limit);

      return {
        decisions: rows.map((row) => ({
          id: row.id,
          method: row.method,
          sender: row.sender,
          outcome: row.outcome,
          reason: row.reason,
          ruleResults: row.ruleResults,
          feeWei: row.feeWei,
          createdAt: row.createdAt.toISOString(),
        })),
      };
    },
  );
}
