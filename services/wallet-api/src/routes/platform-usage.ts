import type { FastifyInstance, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db/index.js";
import type { ChainRegistry } from "../services/chains.js";
import {
	readUsage,
	USAGE_DEFAULT_DAYS,
	USAGE_MAX_DAYS,
} from "../services/usage.js";

const DAY_MS = 86_400_000;

const errorSchema = z
	.object({ error: z.string(), message: z.string() })
	.passthrough();

const figuresSchema = z.object({
	decisions: z.object({
		allowed: z.number().int(),
		refused: z.number().int(),
		/** Whose to fix: the tenant's rules or funds, or the platform. */
		refusedBy: z.object({
			rules: z.number().int(),
			funds: z.number().int(),
			platform: z.number().int(),
			other: z.number().int(),
		}),
		byReason: z.record(z.string(), z.number().int()),
	}),
	settled: z.number().int(),
	reverted: z.number().int(),
	gasWei: z.string(),
	feeWei: z.string(),
	overheadWei: z.string(),
});

/**
 * Sponsorship usage for one chain over a range (B4, openspec platform-usage-metrics), in total and
 * per tenant, from the decisions and settlements wallet-api records. Never reads the chain. Rate
 * limited with the other platform admin calls; the range is capped so the query stays on its index.
 */
export default async function platformUsageRoutes(
	instance: FastifyInstance,
	opts: { db: Db; config: AppConfig; registry: ChainRegistry },
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	app.addHook("onRequest", app.requirePlatformAdmin);

	app.get(
		"/v1/platform/usage",
		{
			config: {
				rateLimit: {
					max: opts.config.PLATFORM_RATE_LIMIT_PER_MINUTE,
					timeWindow: "1 minute",
					keyGenerator: (request: FastifyRequest) =>
						`platform-session:${request.platformAdmin?.sessionId ?? "none"}`,
				},
			},
			schema: {
				tags: ["platform"],
				security: [{ platformSession: [] }],
				summary: `Sponsorship decisions and settlements on one chain, in total and per tenant; the last ${USAGE_DEFAULT_DAYS} days unless given, at most ${USAGE_MAX_DAYS}`,
				querystring: z.object({
					chainId: z.coerce.number().int().positive(),
					since: z.string().datetime({ offset: true }).optional(),
					until: z.string().datetime({ offset: true }).optional(),
				}),
				response: {
					200: z.object({
						chainId: z.number().int(),
						since: z.string(),
						until: z.string(),
						total: figuresSchema,
						tenants: z.array(
							figuresSchema.extend({
								tenantId: z.string(),
								slug: z.string(),
							}),
						),
						/** Settlements for a tenant id this deployment does not know; not in `total`. */
						unknownTenant: figuresSchema,
					}),
					400: errorSchema,
					401: errorSchema,
					404: errorSchema,
				},
			},
		},
		async (request, reply) => {
			const { chainId } = request.query;
			if (!opts.registry.tryGet(chainId))
				return reply.code(404).send({
					error: "unknown-chain",
					message: `this deployment does not serve chain ${chainId}`,
				});
			const until = request.query.until
				? new Date(request.query.until)
				: new Date();
			const since = request.query.since
				? new Date(request.query.since)
				: new Date(until.getTime() - USAGE_DEFAULT_DAYS * DAY_MS);
			if (since >= until)
				return reply.code(400).send({
					error: "invalid-range",
					message: "since must be before until",
				});
			if (until.getTime() - since.getTime() > USAGE_MAX_DAYS * DAY_MS)
				return reply.code(400).send({
					error: "range-too-long",
					message: `a usage range spans at most ${USAGE_MAX_DAYS} days`,
					maxDays: USAGE_MAX_DAYS,
				});
			const usage = await readUsage(opts.db, { chainId, since, until });
			return {
				chainId,
				since: since.toISOString(),
				until: until.toISOString(),
				total: usage.total,
				tenants: usage.tenants,
				unknownTenant: usage.unknownTenant,
			};
		},
	);
}
