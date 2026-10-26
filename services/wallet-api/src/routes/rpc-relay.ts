import type { FastifyInstance, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import {
	createReadRelay,
	type JsonRpcRequest,
	jsonRpcRequestSchema,
	jsonRpcResponseSchema,
	type RelayLabels,
} from "../services/rpc-read-relay.js";

/**
 * The node read relay: what a wallet origin points its chain RPC client at.
 *
 * Reads are public chain state, so this is tenant-bound (by Origin) rather than session-bound —
 * the wallet reads before anyone has signed in (address derivation, fee estimation, the silent
 * restore). What it adds over dialling a node directly: the RPC URL — and any API key in it —
 * lives only in this process, and a wallet origin needs no chain configuration of its own.
 * What may be forwarded is decided in services/rpc-read-relay.ts, shared with the platform relay.
 *
 * Chain in the path, as for the bundler relay: `/v1/rpc/:chainId`; `/v1/rpc` is the
 * single-chain affordance (MC-53).
 */
export default async function rpcRelayRoutes(
	instance: FastifyInstance,
	opts: { config: AppConfig },
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	const { config } = opts;

	const relay = createReadRelay({
		limitPerMinute: config.RPC_RELAY_RATE_LIMIT_PER_MINUTE,
		limitMessage: `tenant RPC relay limit of ${config.RPC_RELAY_RATE_LIMIT_PER_MINUTE}/minute exceeded`,
		count: (labels: RelayLabels<{ tenant: string }>) =>
			app.metrics.rpcRelay.inc(labels),
	});

	const handle = (request: FastifyRequest) => {
		const tenant = request.tenant!;
		return relay.handle({
			body: request.body as JsonRpcRequest,
			chain: request.chain!,
			key: tenant.id,
			log: request.log,
			labels: { tenant: tenant.slug },
		});
	};

	const schema = {
		tags: ["rpc"],
		summary: "Chain RPC read relay (JSON-RPC)",
		description:
			"Forwards read-only JSON-RPC methods to the chain node wallet-api is configured with, so a wallet origin needs no RPC " +
			"URL of its own and a keyed provider URL never reaches a browser. Tenant-bound by Origin, rate-limited per tenant; " +
			"eth_chainId is answered from configuration; anything outside the read allowlist is refused with -32601.",
		body: jsonRpcRequestSchema,
		response: {
			200: jsonRpcResponseSchema,
			400: z.object({
				error: z.string(),
				message: z.string(),
				servedChainIds: z.array(z.number()).optional(),
			}),
			403: z.object({ error: z.string(), message: z.string() }),
			503: z.object({ error: z.string(), message: z.string() }),
		},
	};

	app.post(
		"/v1/rpc/:chainId",
		{
			preHandler: [app.requireTenant, app.requireChain],
			schema: {
				...schema,
				params: z.object({ chainId: z.coerce.number().int().positive() }),
			},
		},
		handle,
	);

	app.post(
		"/v1/rpc",
		{ preHandler: [app.requireTenant, app.requireChain], schema },
		handle,
	);
}
