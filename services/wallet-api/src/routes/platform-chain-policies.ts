import type { FastifyInstance, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import { requirePlatformAdminOf } from "../plugins/auth.js";
import {
	CHAIN_POLICY_FIELDS,
	type ChainPolicyService,
	ChainPolicyWriteError,
	type ResolvedChainPolicy,
	type StoredChainPolicyRow,
	storedChainPolicySchema,
} from "../services/chain-policy.js";
import { actorOf } from "../services/tenant-admin.js";

const HISTORY_PAGE_SIZE = 50;

const errorSchema = z
	.object({ error: z.string(), message: z.string() })
	.passthrough();
const errors = {
	400: errorSchema,
	401: errorSchema,
	404: errorSchema,
	412: errorSchema,
	428: errorSchema,
};

const chainParams = z.object({ chainId: z.coerce.number().int().positive() });

const fieldValue = z.union([z.string(), z.array(z.string())]).nullable();

const fieldSchema = z.object({
	/** What the relay applies; null when the field is undecided in production. */
	effective: fieldValue,
	/**
	 * `override` (see `overriddenBy`), `stored`, `fallback` (undecided, outside production: the
	 * permissive value wallet-api applied before), or `undecided` (production: the chain is refused).
	 */
	source: z.enum(["override", "stored", "fallback", "undecided"]),
	/** `GIANO_CHAINS`, or the env var's name. */
	overriddenBy: z.string().nullable(),
	/** The stored value, which applies once nothing overrides it; null when the row does not set it. */
	stored: fieldValue,
});

const chainPolicySchema = z.object({
	chainId: z.number().int(),
	name: z.string(),
	/** 0 when the chain has no stored row; send it in If-Match to create one. */
	version: z.number().int(),
	/** The stored row as it is, even when it does not parse (see `problems`). */
	stored: z.record(z.string(), z.unknown()).nullable(),
	updatedAt: z.string().nullable(),
	updatedBy: z.string().nullable(),
	fields: z.object(
		Object.fromEntries(
			CHAIN_POLICY_FIELDS.map((field) => [field, fieldSchema]),
		) as Record<(typeof CHAIN_POLICY_FIELDS)[number], typeof fieldSchema>,
	),
	/** Why the chain's operations are refused under `chain-policy`; empty when they are not. */
	problems: z.array(z.string()),
});

type ChainPolicyView = z.infer<typeof chainPolicySchema>;

function chainView(
	chain: { chainId: number; name: string },
	row: StoredChainPolicyRow | undefined,
	resolved: ResolvedChainPolicy,
): ChainPolicyView {
	const stored =
		row && typeof row.policy === "object" && row.policy !== null
			? (row.policy as Record<string, unknown>)
			: null;
	const storedValue = (field: string) => {
		const value = stored?.[field];
		return typeof value === "string" ||
			(Array.isArray(value) && value.every((v) => typeof v === "string"))
			? (value as string | string[])
			: null;
	};
	return {
		chainId: chain.chainId,
		name: chain.name,
		version: row?.version ?? 0,
		stored,
		updatedAt: row?.updatedAt.toISOString() ?? null,
		updatedBy: row?.updatedBy ?? null,
		fields: Object.fromEntries(
			CHAIN_POLICY_FIELDS.map((field) => {
				const { value, from } = resolved.fields[field];
				return [
					field,
					{
						effective: value,
						source: from.kind,
						overriddenBy: from.kind === "override" ? from.source : null,
						stored: storedValue(field),
					},
				];
			}),
		) as ChainPolicyView["fields"],
		problems: resolved.problems,
	};
}

function ifMatchVersion(request: FastifyRequest): number | null | undefined {
	const header = request.headers["if-match"];
	if (header === undefined) return undefined;
	const match = /^(?:W\/)?"?(\d+)"?$/.exec(String(header).trim());
	return match ? Number(match[1]) : null;
}

/**
 * Each served chain's relay policy (openspec chain-relay-policy-console). Platform admins read it,
 * replace the stored policy, and read its history. Every route needs a platform admin session and is
 * rate limited per session, like the rest of the platform tier.
 */
export default async function platformChainPolicyRoutes(
	instance: FastifyInstance,
	opts: { config: AppConfig; chainPolicies: ChainPolicyService },
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	const { chainPolicies } = opts;
	app.addHook("onRequest", app.requirePlatformAdmin);

	const route = {
		config: {
			rateLimit: {
				max: opts.config.PLATFORM_RATE_LIMIT_PER_MINUTE,
				timeWindow: "1 minute",
				keyGenerator: (request: FastifyRequest) =>
					`platform-session:${request.platformAdmin?.sessionId ?? "none"}`,
			},
		},
	};
	const docs = { tags: ["platform"], security: [{ platformSession: [] }] };

	app.get(
		"/v1/platform/chain-policies",
		{
			...route,
			schema: {
				...docs,
				summary:
					"Every served chain's relay policy: stored, overrides, effective, problems",
				response: {
					200: z.object({ chains: z.array(chainPolicySchema) }),
					...errors,
				},
			},
		},
		async () => ({
			chains: (await chainPolicies.list()).map(({ chain, row, resolved }) =>
				chainView(chain, row, resolved),
			),
		}),
	);

	app.put(
		"/v1/platform/chain-policies/:chainId",
		{
			...route,
			schema: {
				...docs,
				summary:
					"Replace a chain's stored relay policy; requires If-Match with the current version",
				params: chainParams,
				body: storedChainPolicySchema,
				response: { 200: chainPolicySchema, ...errors },
			},
		},
		async (request, reply) => {
			const version = ifMatchVersion(request);
			if (version === undefined)
				return reply.code(428).send({
					error: "precondition-required",
					message:
						"If-Match with the chain policy's version is required (0 when it has none)",
				});
			if (version === null)
				return reply.code(412).send({
					error: "version-mismatch",
					message: 'If-Match must carry the chain policy version, e.g. "3"',
				});
			const admin = requirePlatformAdminOf(request);
			try {
				const { chain, row, resolved } = await chainPolicies.replace(
					request.params.chainId,
					request.body,
					version,
					{ actor: actorOf(admin), platformAdminSessionId: admin.sessionId },
				);
				request.log.info(
					{
						chainId: chain.chainId,
						version: row.version,
						actor: actorOf(admin),
						problems: resolved.problems,
					},
					"chain relay policy replaced",
				);
				return reply
					.header("etag", `"${row.version}"`)
					.send(chainView(chain, row, resolved));
			} catch (error) {
				if (!(error instanceof ChainPolicyWriteError)) throw error;
				return reply
					.code(error.status)
					.send({ error: error.code, message: error.message, ...error.detail });
			}
		},
	);

	app.get(
		"/v1/platform/chain-policies/:chainId/history",
		{
			...route,
			schema: {
				...docs,
				summary:
					"Every write to the chain's relay policy, newest first, 50 per page",
				params: chainParams,
				querystring: z.object({ before: z.string().uuid().optional() }),
				response: {
					200: z.object({
						entries: z.array(
							z.object({
								id: z.string(),
								action: z.string(),
								actor: z.string(),
								platformAdminSessionId: z.string().nullable(),
								before: z.record(z.string(), z.unknown()).nullable(),
								after: z.record(z.string(), z.unknown()),
								createdAt: z.string(),
							}),
						),
						next: z.string().nullable(),
					}),
					...errors,
				},
			},
		},
		async (request, reply) => {
			if (!chainPolicies.serves(request.params.chainId))
				return reply.code(404).send({
					error: "unknown-chain",
					message: `wallet-api does not serve chain ${request.params.chainId}`,
				});
			const page = await chainPolicies.history(
				request.params.chainId,
				request.query.before,
				HISTORY_PAGE_SIZE,
			);
			return {
				next: page.next,
				entries: page.entries.map((entry) => ({
					id: entry.id,
					action: entry.action,
					actor: entry.actor,
					platformAdminSessionId: entry.platformAdminSessionId,
					before: entry.before as Record<string, unknown> | null,
					after: entry.after as Record<string, unknown>,
					createdAt: entry.createdAt.toISOString(),
				})),
			};
		},
	);
}
