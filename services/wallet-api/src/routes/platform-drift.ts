import type { FastifyInstance, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db/index.js";
import type { ChainRegistry } from "../services/chains.js";
import {
	type ChainDrift,
	computeDrift,
	type DriftStore,
} from "../services/drift.js";

const errorSchema = z
	.object({ error: z.string(), message: z.string() })
	.passthrough();

/**
 * The drift between wallet-api's registry and ledger and each paymaster (B5, openspec
 * tenant-chain-drift). Reported, never a health failure: who acts on it is the alerting non-goal.
 *
 * The watcher computes it each pass on the replica that holds that chain's lock. Another replica,
 * or one whose watcher has not run yet, computes it here from the same database and chain, so the
 * answer does not depend on which replica the request reached.
 */
export default async function platformDriftRoutes(
	instance: FastifyInstance,
	opts: {
		db: Db;
		config: AppConfig;
		registry: ChainRegistry;
		drift: DriftStore;
	},
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	app.addHook("onRequest", app.requirePlatformAdmin);

	const view = (drift: ChainDrift) => ({
		chainId: drift.chainId,
		checkedAt: drift.checkedAt.toISOString(),
		entries: drift.entries,
		unchecked: drift.unchecked,
	});

	app.get(
		"/v1/platform/drift",
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
				summary:
					"Where the registry and ledger disagree with each sponsoring chain's paymaster: unknown tenants, enabled state, ledger balance and withdrawal address",
				response: {
					200: z.object({
						chains: z.array(
							z.object({
								chainId: z.number().int(),
								checkedAt: z.string(),
								entries: z.array(z.object({ kind: z.string() }).passthrough()),
								/** Tenants the chain could not be read for at the ledger's block. */
								unchecked: z.array(z.string()),
							}),
						),
					}),
					401: errorSchema,
					502: errorSchema,
				},
			},
		},
		async (request, reply) => {
			try {
				const chains = await Promise.all(
					opts.registry.all
						.filter((chain) => chain.paymaster)
						.map(
							async (chain) =>
								opts.drift.get(chain.chainId) ??
								computeDrift({
									db: opts.db,
									chainId: chain.chainId,
									// biome-ignore lint/style/noNonNullAssertion: filtered to sponsoring chains above
									paymaster: chain.paymaster!,
								}),
						),
				);
				return { chains: chains.map(view) };
			} catch (error) {
				request.log.warn({ err: error }, "drift could not be computed");
				return reply.code(502).send({
					error: "chain-unreachable",
					message: "a paymaster could not be read to compare against",
				});
			}
		},
	);
}
