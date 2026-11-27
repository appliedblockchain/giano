import { and, desc, eq, sql } from "drizzle-orm";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db/index.js";
import {
	sponsorshipDecisions,
	sponsorshipSettlements,
	tenantSponsorship,
	tenantSponsorshipHistory,
} from "../db/schema.js";
import { requireAdminTenantOf } from "../plugins/auth.js";
import { requireChainOf } from "../plugins/chain.js";
import type { ChainRegistry } from "../services/chains.js";
import {
	type PaymasterReader,
	tenantIdToBytes16,
} from "../services/paymaster-contract.js";
import {
	checkWalletManagementCap,
	formatConfigIssues,
	type SponsorshipConfig,
	sponsorshipConfigSchema,
} from "../services/sponsorship-config.js";
import type { LedgerService } from "../services/sponsorship-ledger.js";
import {
	legacyAllowlist,
	lockTenantRules,
	RuleWriteError,
	replaceLegacyRules,
} from "../services/sponsorship-rule-store.js";
import { sha256hex } from "../services/tenants.js";
import { ifMatchVersion } from "./if-match.js";

/** A settings write whose `If-Match` names a version other than the stored one. */
class VersionMismatch extends Error {
	constructor(readonly currentVersion: number) {
		super(`settings are at version ${currentVersion}`);
	}
}

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
	opts: {
		db: Db;
		config: AppConfig;
		ledger: LedgerService;
		registry: ChainRegistry;
	},
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	// requireChain runs after requireAdmin: with one chain configured the parameter is
	// supplied automatically, so an on-premises tenant never encounters the dimension (MC-53);
	// with several it is required, because a tenant's rules, balance and history are all
	// per chain (MC-66) and guessing which one was meant is exactly what MC-53 forbids.
	app.addHook("preHandler", app.requireAdmin);
	app.addHook("preHandler", app.requireChain);

	const { db, config, ledger } = opts;
	const walletManagementCapWei = config.SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI;

	const wei = z.string();
	const errorBody = z.object({ error: z.string(), message: z.string() });
	/** Selects the chain when several are served; supplied automatically when one is (MC-53). */
	const chainQuery = z.object({
		chainId: z.coerce.number().int().positive().optional(),
	});

	const keyHashOf = (request: { headers: { authorization?: string } }) => {
		const header = request.headers.authorization;
		if (!header?.startsWith("Bearer ")) return null;
		return sha256hex(header.slice("Bearer ".length).trim());
	};

	/**
	 * Writes the new settings and appends them to the history, in one transaction. A deprecated
	 * `allowlist` in them replaces the legacy rules in the same transaction, and the stored value's
	 * `allowlist` is rewritten as the mirror of the legacy rules (design D8). Returns what was stored,
	 * or the refusal of the rules write.
	 */
	async function writeConfig(
		tenantId: string,
		chainId: number,
		nextConfig: SponsorshipConfig,
		keyHash: string | null,
		expectedVersion: number | undefined,
	): Promise<
		| { ok: true; config: SponsorshipConfig; version: number }
		| { ok: false; error: RuleWriteError }
		| { ok: false; currentVersion: number }
	> {
		try {
			const stored = await db.transaction(async (tx) => {
				// Checked first, under the tenant's rule lock, so a stale write changes no rule either. The
				// lock also serialises two first writes, where there is no row to lock yet.
				if (expectedVersion !== undefined) {
					await lockTenantRules(tx, tenantId, chainId);
					const [current] = await tx
						.select({ version: tenantSponsorship.version })
						.from(tenantSponsorship)
						.where(
							and(
								eq(tenantSponsorship.tenantId, tenantId),
								eq(tenantSponsorship.chainId, chainId),
							),
						);
					const currentVersion = current?.version ?? 0;
					if (currentVersion !== expectedVersion)
						throw new VersionMismatch(currentVersion);
				}
				if (nextConfig.allowlist !== undefined) {
					await replaceLegacyRules(tx, {
						tenantId,
						chainId,
						allowlist: nextConfig.allowlist,
						keyHash,
						now: new Date(),
						maxRules: config.SPONSORSHIP_MAX_RULES_PER_CHAIN,
					});
				}
				const value: SponsorshipConfig = {
					...nextConfig,
					allowlist: await legacyAllowlist(tx, tenantId, chainId),
				};

				await tx.insert(tenantSponsorshipHistory).values({
					tenantId,
					chainId,
					config: value,
					createdByKeyHash: keyHash,
				});
				const [written] = await tx
					.insert(tenantSponsorship)
					.values({
						tenantId,
						chainId,
						config: value,
						updatedByKeyHash: keyHash,
						version: 1,
					})
					.onConflictDoUpdate({
						target: [tenantSponsorship.tenantId, tenantSponsorship.chainId],
						set: {
							config: value,
							updatedAt: new Date(),
							updatedByKeyHash: keyHash,
							version: sql`${tenantSponsorship.version} + 1`,
						},
					})
					.returning({ version: tenantSponsorship.version });
				return { value, version: written.version };
			});
			return { ok: true, config: stored.value, version: stored.version };
		} catch (error) {
			if (error instanceof RuleWriteError) return { ok: false, error };
			if (error instanceof VersionMismatch)
				return { ok: false, currentVersion: error.currentVersion };
			throw error;
		}
	}

	/**
	 * Answers a refused settings write: a stale `If-Match` (412, with the current version) or a
	 * deprecated allowlist the rules refused (400).
	 */
	function sendWriteRefusal(
		reply: FastifyReply,
		refusal: { error: RuleWriteError } | { currentVersion: number },
	) {
		if ("currentVersion" in refusal)
			return reply.code(412).send({
				error: "version-mismatch",
				message: `the settings are at version ${refusal.currentVersion}; read them again and retry`,
				currentVersion: refusal.currentVersion,
			});
		return reply.code(400).send(allowlistRefusal(refusal.error));
	}

	/**
	 * The `If-Match` version of a settings write: a number, undefined when absent (accepted, and
	 * deprecated), or a 412 already sent for a value that is not a version.
	 */
	function expectedVersionOf(
		request: FastifyRequest,
		reply: FastifyReply,
	): number | undefined | "sent" {
		const version = ifMatchVersion(request);
		if (version !== null) return version;
		reply.code(412).send({
			error: "version-mismatch",
			message: 'If-Match must carry the settings version, e.g. "3"',
		});
		return "sent";
	}

	/** The 400 a refused deprecated allowlist write answers. */
	const allowlistRefusal = (error: RuleWriteError) => ({
		error: "validation",
		message: "sponsorship configuration is not valid",
		issues: [{ path: "allowlist", message: error.message }],
	});

	// ── Rules ──────────────────────────────────────────────────────────────────

	app.get(
		"/v1/admin/sponsorship",
		{
			schema: {
				tags: ["admin"],
				summary: "Read this tenant's sponsorship rules",
				security: [{ adminKey: [] }],
				querystring: chainQuery,
				response: {
					200: z.object({
						configured: z.boolean(),
						config: z.unknown(),
						updatedAt: z.string().nullable(),
						/** Send it back as `If-Match` on a write, so a concurrent edit is refused rather than lost. */
						version: z.number(),
						/** True when the stored value no longer validates — which means NO sponsorship, not permissive. */
						valid: z.boolean(),
						issues: z
							.array(z.object({ path: z.string(), message: z.string() }))
							.optional(),
					}),
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const [row] = await db
				.select({
					config: tenantSponsorship.config,
					updatedAt: tenantSponsorship.updatedAt,
					version: tenantSponsorship.version,
				})
				.from(tenantSponsorship)
				.where(
					and(
						eq(tenantSponsorship.tenantId, tenant.id),
						eq(tenantSponsorship.chainId, chainId),
					),
				);

			reply.header("etag", `"${row?.version ?? 0}"`);
			if (!row) {
				return {
					configured: false,
					config: { enabled: false, allowlist: [] },
					updatedAt: null,
					version: 0,
					valid: true,
				};
			}

			const parsed = sponsorshipConfigSchema.safeParse(row.config);
			return {
				configured: true,
				config: row.config,
				updatedAt: row.updatedAt.toISOString(),
				version: row.version,
				valid: parsed.success,
				...(parsed.success ? {} : { issues: formatConfigIssues(parsed.error) }),
			};
		},
	);

	app.put(
		"/v1/admin/sponsorship",
		{
			schema: {
				tags: ["admin"],
				summary: "Replace this tenant's sponsorship rules (for one chain)",
				description:
					"Full replace of the settings, validated on write. Rejected with per-path messages on any violation, so an " +
					"invalid configuration is never stored and therefore never interpreted permissively. Settings are per chain " +
					"and never inherited from another chain (MC-67): enabling a new chain is an explicit act. Send the version " +
					'from GET as If-Match ("3"): a stale one is refused with 412. A write without If-Match is accepted and ' +
					"deprecated. The contracts sponsored are rules (/v1/admin/sponsorship/rules); `allowlist` here is " +
					"deprecated, and replaces only the rules with neither a clientReference nor an expiresAt.",
				security: [{ adminKey: [] }],
				querystring: chainQuery,
				body: z.unknown(),
				response: {
					200: z.object({
						config: z.unknown(),
						updatedAt: z.string(),
						version: z.number(),
					}),
					412: z.object({
						error: z.string(),
						message: z.string(),
						currentVersion: z.number().optional(),
					}),
					400: z.object({
						error: z.string(),
						message: z.string(),
						issues: z.array(
							z.object({ path: z.string(), message: z.string() }),
						),
					}),
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const parsed = sponsorshipConfigSchema.safeParse(request.body);
			if (!parsed.success) {
				return reply.code(400).send({
					error: "validation",
					message: "sponsorship configuration is not valid",
					issues: formatConfigIssues(parsed.error),
				});
			}

			// Wallet management is platform-governed, so a tenant may lower its cap and never raise it.
			// Rejected rather than clamped: a tenant that asked for a cap and silently got a different
			// one has no way to discover that.
			const capIssues = checkWalletManagementCap(
				parsed.data,
				walletManagementCapWei,
			);
			if (capIssues.length > 0) {
				return reply.code(400).send({
					error: "validation",
					message: "sponsorship configuration is not valid",
					issues: capIssues,
				});
			}

			const expectedVersion = expectedVersionOf(request, reply);
			if (expectedVersion === "sent") return reply;
			const chain = requireChainOf(request);
			const written = await writeConfig(
				tenant.id,
				chain.chainId,
				parsed.data,
				keyHashOf(request),
				expectedVersion,
			);
			if (!written.ok) return sendWriteRefusal(reply, written);

			// The reservation statement joins against this row, so a tenant that has just enabled
			// sponsorship must have one — otherwise its first operation is refused for a reason that
			// looks nothing like "you have not funded a balance yet".
			if (chain.paymaster) {
				await ledger.ensureTenantRow({
					tenantId: tenant.id,
					chainId: chain.chainId,
					paymasterAddress: chain.paymaster.address,
				});
			}

			request.log.info(
				{
					sponsorship: "config-replaced",
					enabled: parsed.data.enabled,
					chainId: chain.chainId,
				},
				"sponsorship configuration updated",
			);
			return reply.header("etag", `"${written.version}"`).send({
				config: written.config,
				updatedAt: new Date().toISOString(),
				version: written.version,
			});
		},
	);

	app.patch(
		"/v1/admin/sponsorship",
		{
			schema: {
				tags: ["admin"],
				summary:
					"Update fields of this tenant's sponsorship rules (for one chain)",
				description:
					"Shallow field-level merge over the stored settings, then validated as a whole — so a partial " +
					"update cannot leave the settings in a state a full replace would have rejected. If-Match and the " +
					"deprecated `allowlist` behave as on PUT.",
				security: [{ adminKey: [] }],
				querystring: chainQuery,
				body: z.record(z.string(), z.unknown()),
				response: {
					200: z.object({
						config: z.unknown(),
						updatedAt: z.string(),
						version: z.number(),
					}),
					412: z.object({
						error: z.string(),
						message: z.string(),
						currentVersion: z.number().optional(),
					}),
					400: z.object({
						error: z.string(),
						message: z.string(),
						issues: z.array(
							z.object({ path: z.string(), message: z.string() }),
						),
					}),
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chain = requireChainOf(request);
			const chainId = chain.chainId;
			const [row] = await db
				.select({ config: tenantSponsorship.config })
				.from(tenantSponsorship)
				.where(
					and(
						eq(tenantSponsorship.tenantId, tenant.id),
						eq(tenantSponsorship.chainId, chainId),
					),
				);

			const merged = {
				...((row?.config as Record<string, unknown>) ?? {}),
				...request.body,
			};
			const parsed = sponsorshipConfigSchema.safeParse(merged);
			if (!parsed.success) {
				return reply.code(400).send({
					error: "validation",
					message: "the merged sponsorship configuration is not valid",
					issues: formatConfigIssues(parsed.error),
				});
			}

			const capIssues = checkWalletManagementCap(
				parsed.data,
				walletManagementCapWei,
			);
			if (capIssues.length > 0) {
				return reply.code(400).send({
					error: "validation",
					message: "the merged sponsorship configuration is not valid",
					issues: capIssues,
				});
			}

			const expectedVersion = expectedVersionOf(request, reply);
			if (expectedVersion === "sent") return reply;
			const written = await writeConfig(
				tenant.id,
				chainId,
				parsed.data,
				keyHashOf(request),
				expectedVersion,
			);
			if (!written.ok) return sendWriteRefusal(reply, written);
			if (chain.paymaster) {
				await ledger.ensureTenantRow({
					tenantId: tenant.id,
					chainId,
					paymasterAddress: chain.paymaster.address,
				});
			}
			return reply.header("etag", `"${written.version}"`).send({
				config: written.config,
				updatedAt: new Date().toISOString(),
				version: written.version,
			});
		},
	);

	app.get(
		"/v1/admin/sponsorship/history",
		{
			schema: {
				tags: ["admin"],
				summary: "Who changed the sponsorship rules, and when",
				security: [{ adminKey: [] }],
				querystring: chainQuery.extend({
					limit: z.coerce.number().int().min(1).max(200).default(50),
				}),
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
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const rows = await db
				.select()
				.from(tenantSponsorshipHistory)
				.where(
					and(
						eq(tenantSponsorshipHistory.tenantId, tenant.id),
						eq(tenantSponsorshipHistory.chainId, chainId),
					),
				)
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
		"/v1/admin/sponsorship/balance",
		{
			schema: {
				tags: ["admin"],
				summary: "This tenant's gas balance, reservations and where to fund",
				description:
					"Read live from the paymaster contract, with the block it was read at, so the figures can be " +
					"reproduced from the chain rather than taken on trust.",
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
						fundingInstructions: z.object({
							to: z.string(),
							call: z.string(),
							tenantId: z.string(),
						}),
					}),
					503: errorBody,
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chain = requireChainOf(request);
			const chainId = chain.chainId;
			const paymaster = chain.paymaster;
			if (!paymaster) {
				return reply.code(503).send({
					error: "sponsorship-disabled",
					message: `gas sponsorship is not enabled on chain ${chainId}`,
				});
			}

			const tenantId = tenantIdToBytes16(tenant.id);
			let onChain: Awaited<ReturnType<PaymasterReader["tenant"]>>;
			let blockNumber: bigint;
			try {
				[onChain, blockNumber] = await Promise.all([
					paymaster.tenant(tenantId),
					paymaster.blockNumber(),
				]);
			} catch (error) {
				return reply.code(503).send({
					error: "chain-unreachable",
					message: (error as Error).message,
				});
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
		"/v1/admin/sponsorship/spend",
		{
			schema: {
				tags: ["admin"],
				summary: "What this tenant has been charged, broken down",
				description:
					"One row per settled operation, with gas, Giano's fee and the overhead allowance kept separate — " +
					"each row traceable to a `Sponsored` event on chain.",
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
						totals: z.object({
							gasCostWei: wei,
							feeWei: wei,
							overheadWei: wei,
							totalWei: wei,
							count: z.number(),
						}),
					}),
				},
			},
		},
		async (request) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const conditions = [
				eq(sponsorshipSettlements.tenantId, tenant.id),
				eq(sponsorshipSettlements.chainId, chainId),
			];
			if (request.query.before) {
				conditions.push(
					sql`${sponsorshipSettlements.observedAt} < ${new Date(request.query.before)}`,
				);
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
				.where(
					and(
						eq(sponsorshipSettlements.tenantId, tenant.id),
						eq(sponsorshipSettlements.chainId, chainId),
					),
				);

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
		"/v1/admin/sponsorship/decisions",
		{
			schema: {
				tags: ["admin"],
				summary:
					"Every sponsorship decision, allowed or refused, with the rule-by-rule results",
				description:
					"Includes the pre-approval checks that never became transactions — those are exactly the decisions a " +
					'user was shown, so they are what answers "why did my user see a refusal?".',
				security: [{ adminKey: [] }],
				querystring: chainQuery.extend({
					limit: z.coerce.number().int().min(1).max(500).default(100),
					outcome: z.enum(["allowed", "refused"]).optional(),
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
								/** The rules that allowed the operation's application calls. */
								ruleIds: z.array(z.string()),
								feeWei: wei.nullable(),
								createdAt: z.string(),
							}),
						),
					}),
				},
			},
		},
		async (request) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const conditions = [
				eq(sponsorshipDecisions.tenantId, tenant.id),
				eq(sponsorshipDecisions.chainId, chainId),
			];
			if (request.query.outcome)
				conditions.push(
					eq(sponsorshipDecisions.outcome, request.query.outcome),
				);

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
					ruleIds: row.ruleIds,
					feeWei: row.feeWei,
					createdAt: row.createdAt.toISOString(),
				})),
			};
		},
	);
}
