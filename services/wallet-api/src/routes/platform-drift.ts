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
 * The watcher computes it before each reconcile on the replica that holds that chain's lock. Its
 * result is served while it is no older than two reconcile intervals; another replica, one whose
 * watcher has not run yet, or one whose last result is older (a watcher that stopped or lost its
 * lock) computes it here from the same database and chain. Each chain answers on its own: one that
 * cannot be read is an error for that chain, not for every chain.
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
	const maxAgeMs = 2 * opts.config.PAYMASTER_RECONCILE_INTERVAL_MS;

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
							z.union([
								z.object({
									chainId: z.number().int(),
									checkedAt: z.string(),
									entries: z.array(
										z.object({ kind: z.string() }).passthrough(),
									),
									/** Tenants not compared: the chain could not be read at the ledger's block, or the row is not yet synced. */
									unchecked: z.array(z.string()),
								}),
								z.object({
									chainId: z.number().int(),
									/** This chain's drift could not be computed; a fixed message, never the cause. */
									error: z.literal("drift-unavailable"),
									message: z.string(),
								}),
							]),
						),
					}),
					401: errorSchema,
				},
			},
		},
		async (request) => {
			const sponsoring = opts.registry.all.filter((chain) => chain.paymaster);
			const results = await Promise.allSettled(
				sponsoring.map((chain) =>
					opts.drift.fresh(chain.chainId, maxAgeMs, () =>
						computeDrift({
							db: opts.db,
							chainId: chain.chainId,
							// biome-ignore lint/style/noNonNullAssertion: filtered to sponsoring chains above
							paymaster: chain.paymaster!,
						}),
					),
				),
			);
			return {
				chains: results.map((result, index) => {
					if (result.status === "fulfilled") return view(result.value);
					const { chainId } = sponsoring[index];
					request.log.warn(
						{ err: result.reason, chainId },
						"drift could not be computed",
					);
					return {
						chainId,
						error: "drift-unavailable" as const,
						message:
							"the paymaster or wallet-api's records could not be read to compare",
					};
				}),
			};
		},
	);
}
