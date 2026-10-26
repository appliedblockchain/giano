import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { parseSiweMessage } from "viem/siwe";
import { z } from "zod";
import { PLATFORM_UNAUTHORIZED } from "../plugins/auth.js";
import type { PlatformSessionService } from "../services/platform-sessions.js";

/**
 * Sign-in is limited per address, so one platform admin's retries never lock another out, and never per
 * IP: with no trustProxy every request arrives from the proxy's address. A deployment-wide ceiling
 * of ten times that, across every address listed or not, bounds the ECDSA work an attacker spraying
 * unlisted addresses can cause while staying far above what real platform admins need.
 */
const SIGN_IN_CEILING_FACTOR = 10;

const unauthorizedSchema = z.object({
	error: z.literal("unauthorized"),
	message: z.string(),
});
const rateLimitedSchema = z.object({ error: z.string(), message: z.string() });

/**
 * Platform admin sign-in with a wallet (EIP-4361; specs/PLATFORM-ADMIN-SPECS.md §4.2). Registered only
 * when the environment has a sign-in domain (src/environments.ts). Challenge and verify are unauthenticated, so they run the
 * Origin refusal only; logout runs the whole guard.
 */
export default async function platformAuthRoutes(
	instance: FastifyInstance,
	opts: {
		platformAdminSessions: PlatformSessionService;
		ratePerMinute: number;
	},
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	app.addHook("onRequest", app.refusePlatformOrigin);

	const ceiling = app.createRateLimit({
		max: opts.ratePerMinute * SIGN_IN_CEILING_FACTOR,
		timeWindow: "1 minute",
		keyGenerator: () => "platform-sign-in",
	});
	const signInLimit = (
		route: string,
		addressOf: (request: FastifyRequest) => string,
	) => ({
		config: {
			rateLimit: {
				// after body parsing, so the key can be the address the request is about
				hook: "preHandler" as const,
				max: opts.ratePerMinute,
				timeWindow: "1 minute",
				keyGenerator: (request: FastifyRequest) =>
					`admin-${route}:${addressOf(request)}`,
			},
		},
		preHandler: async (request: FastifyRequest, reply: FastifyReply) => {
			const limit = await ceiling(request);
			if (!limit.isAllowed && limit.isExceeded) {
				return reply.code(429).send({
					error: "rate-limited",
					message:
						"too many platform admin sign-in attempts; try again shortly",
				});
			}
		},
	});

	app.post(
		"/v1/platform/auth/challenge",
		{
			...signInLimit("challenge", (request) =>
				String(
					(request.body as { address?: string })?.address ?? "",
				).toLowerCase(),
			),
			schema: {
				tags: ["platform"],
				summary:
					"Issue an EIP-4361 sign-in message for a platform admin address",
				body: z.object({
					address: z
						.string()
						.regex(/^0x[0-9a-fA-F]{40}$/, "expected a 0x address"),
					chainId: z.number().int().positive(),
				}),
				response: {
					200: z.object({ message: z.string() }),
					429: rateLimitedSchema,
				},
			},
		},
		async (request) => opts.platformAdminSessions.issueChallenge(request.body),
	);

	app.post(
		"/v1/platform/auth/verify",
		{
			...signInLimit("verify", (request) => {
				try {
					return (
						parseSiweMessage(
							String((request.body as { message?: string })?.message ?? ""),
						).address?.toLowerCase() ?? "malformed"
					);
				} catch {
					return "malformed";
				}
			}),
			schema: {
				tags: ["platform"],
				summary:
					"Exchange a signed sign-in message for a platform admin session",
				body: z.object({
					message: z.string().min(1).max(4096),
					signature: z
						.string()
						.regex(/^0x[0-9a-fA-F]+$/, "expected a 0x hex signature"),
				}),
				response: {
					200: z.object({
						token: z.string(),
						expiresAt: z.string(),
						admin: z.object({ id: z.string(), address: z.string() }),
					}),
					401: unauthorizedSchema,
					429: rateLimitedSchema,
				},
			},
		},
		async (request, reply) => {
			const result = await opts.platformAdminSessions.verify({
				message: request.body.message,
				signature: request.body.signature as `0x${string}`,
			});
			if (!result.ok) {
				app.metrics.platformAuthFailures.inc({ reason: result.reason });
				request.log.info(
					{ reason: result.reason },
					"platform admin sign-in refused",
				);
				return reply.code(401).send(PLATFORM_UNAUTHORIZED);
			}
			const session = await opts.platformAdminSessions.createSession({
				admin: result.admin,
				chainId: result.chainId,
				ip: request.ip,
				userAgent: request.headers["user-agent"],
			});
			request.log.info({ admin: result.admin.id }, "platform admin signed in");
			return {
				token: session.token,
				expiresAt: session.expiresAt.toISOString(),
				admin: result.admin,
			};
		},
	);

	app.post(
		"/v1/platform/auth/logout",
		{
			onRequest: app.requirePlatformAdmin,
			schema: {
				tags: ["platform"],
				summary: "Revoke the presented platform admin session",
				security: [{ platformSession: [] }],
				response: { 204: z.null(), 401: unauthorizedSchema },
			},
		},
		async (request, reply) => {
			await opts.platformAdminSessions.revoke(request.platformAdmin!.sessionId);
			return reply.code(204).send(null);
		},
	);
}
