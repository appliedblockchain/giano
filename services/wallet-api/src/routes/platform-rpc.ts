import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import {
	boundedLogsGuard,
	createReadRelay,
	jsonRpcRequestSchema,
	jsonRpcResponseSchema,
} from "../services/rpc-read-relay.js";

/** A console read is one small JSON-RPC object; anything near this is not one. */
const BODY_LIMIT_BYTES = 16 * 1024;

const errorSchema = z
	.object({ error: z.string(), message: z.string() })
	.passthrough();

/**
 * The platform chain read relay: the only way a hosted paymaster console reads the chain
 * (openspec platform-chain-reads). The console has no backend and used to proxy each chain's keyed
 * provider URL straight from its nginx, which handed that quota to anyone who could reach the page.
 * Here the same read core as the tenant relay sits behind a platform admin session instead of a
 * tenant Origin, so the keyed URL stays in this process and only a signed-in platform admin spends it.
 *
 * Bounded beyond the shared allowlist, because a session is a person and not a wallet origin: a
 * small body, an eth_getLogs span no wider than the console's own log window needs, and a per-session
 * window of its own — separate from PLATFORM_RATE_LIMIT_PER_MINUTE so that polling never locks a
 * platform admin out of the tenant routes. No single-chain `/v1/platform/rpc` affordance: the console
 * always knows its chain.
 */
export default async function platformRpcRoutes(
	instance: FastifyInstance,
	opts: { config: AppConfig },
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	const { config } = opts;
	app.addHook("onRequest", app.requirePlatformAdmin);

	const relay = createReadRelay({
		limitPerMinute: config.PLATFORM_RPC_RATE_LIMIT_PER_MINUTE,
		limitMessage: `platform RPC relay limit of ${config.PLATFORM_RPC_RATE_LIMIT_PER_MINUTE}/minute per session exceeded`,
		guard: boundedLogsGuard(config.PLATFORM_RPC_MAX_LOG_BLOCKS),
		count: (labels) => app.metrics.platformRpcRelay.inc(labels),
	});

	app.post(
		"/v1/platform/rpc/:chainId",
		{
			bodyLimit: BODY_LIMIT_BYTES,
			preHandler: app.requireChain,
			schema: {
				tags: ["platform"],
				security: [{ platformSession: [] }],
				summary: "Chain RPC read relay for platform admins (JSON-RPC)",
				description:
					"What the paymaster console reads the chain through. Forwards the same read-only JSON-RPC methods as /v1/rpc, " +
					`for a platform admin session only. eth_getLogs must name a blockHash or a hex range of at most ${config.PLATFORM_RPC_MAX_LOG_BLOCKS} ` +
					`blocks (-32602 otherwise); ${config.PLATFORM_RPC_RATE_LIMIT_PER_MINUTE} forwarded reads per session per minute (-32021 beyond); ` +
					`bodies over ${BODY_LIMIT_BYTES} bytes are refused with 413.`,
				params: z.object({ chainId: z.coerce.number().int().positive() }),
				body: jsonRpcRequestSchema,
				response: {
					200: jsonRpcResponseSchema,
					400: errorSchema,
					401: errorSchema,
					403: errorSchema,
					413: errorSchema,
					503: errorSchema,
				},
			},
		},
		(request) =>
			relay.handle({
				body: request.body,
				chain: request.chain!,
				// requirePlatformAdmin ran first (an instance hook), so the session is known here
				key: request.platformAdmin!.sessionId,
				log: request.log,
				labels: {},
			}),
	);
}
