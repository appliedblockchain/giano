import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import {
	type PlatformAdmin,
	type PlatformAdminService,
	type PlatformAdminWithSessions,
	platformAdminInputSchema,
	SESSION_HISTORY_DAYS,
} from "../services/platform-admins.js";
import { TenantWriteError } from "../services/tenants.js";

const HISTORY_LIMIT = 100;

const errorSchema = z
	.object({ error: z.string(), message: z.string() })
	.passthrough();
const errors = {
	400: errorSchema,
	401: errorSchema,
	403: errorSchema,
	404: errorSchema,
	409: errorSchema,
};

const adminSchema = z.object({
	id: z.string(),
	address: z.string(),
	addedBy: z.string(),
	createdAt: z.string(),
});
const adminView = (row: PlatformAdmin) => ({
	id: row.id,
	address: row.address,
	addedBy: row.addedBy,
	createdAt: row.createdAt.toISOString(),
});
const listedAdminSchema = adminSchema.extend({
	/** The newest sign-in, or null for an admin who never signed in. */
	lastSignInAt: z.string().nullable(),
	/** Sessions neither expired nor revoked. */
	activeSessions: z.number().int(),
});
const listedAdminView = (row: PlatformAdminWithSessions) => ({
	...adminView(row),
	lastSignInAt: row.lastSignInAt?.toISOString() ?? null,
	activeSessions: row.activeSessions,
});
const sessionSchema = z.object({
	id: z.string(),
	createdAt: z.string(),
	expiresAt: z.string(),
	revokedAt: z.string().nullable(),
	chainId: z.number().int(),
	/** Null for another admin's session: they see when it was signed, not where from. */
	ip: z.string().nullable(),
	/** Null for another admin's session, as `ip`. */
	userAgent: z.string().nullable(),
	/** The session making this request. */
	current: z.boolean(),
});

function sendWriteError(reply: FastifyReply, error: unknown) {
	if (!(error instanceof TenantWriteError)) throw error;
	return reply
		.code(error.status)
		.send({ error: error.code, message: error.message, ...error.detail });
}

/**
 * The platform admins themselves (specs/PLATFORM-ADMIN-SPECS.md §4.1): list, add, remove and history.
 * Registered with the rest of the platform tier. Every route needs a platform admin session, refuses an
 * Origin, and is rate limited per session. Removing the last platform admin, or yourself, is refused.
 */
export default async function platformAdminRoutes(
	instance: FastifyInstance,
	opts: { admins: PlatformAdminService; config: AppConfig },
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
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
		"/v1/platform/admins",
		{
			...route,
			schema: {
				...docs,
				summary:
					"The platform admins, oldest first, with each one's last sign-in and open sessions",
				response: {
					200: z.object({ admins: z.array(listedAdminSchema) }),
					...errors,
				},
			},
		},
		async () => ({ admins: (await opts.admins.list()).map(listedAdminView) }),
	);

	app.get(
		"/v1/platform/admins/:id/sessions",
		{
			...route,
			schema: {
				...docs,
				summary: `A platform admin's sessions from the last ${SESSION_HISTORY_DAYS} days, newest first; never a token or its hash, and the IP and user agent only of your own`,
				params: z.object({ id: z.string().min(1).max(64) }),
				response: {
					200: z.object({ sessions: z.array(sessionSchema) }),
					...errors,
				},
			},
		},
		async (request, reply) => {
			try {
				const rows = await opts.admins.sessions(
					request.params.id,
					request.platformAdmin!,
				);
				return {
					sessions: rows.map((row) => ({
						id: row.id,
						createdAt: row.createdAt.toISOString(),
						expiresAt: row.expiresAt.toISOString(),
						revokedAt: row.revokedAt?.toISOString() ?? null,
						chainId: row.chainId,
						ip: row.ip,
						userAgent: row.userAgent,
						current: row.id === request.platformAdmin?.sessionId,
					})),
				};
			} catch (error) {
				return sendWriteError(reply, error);
			}
		},
	);

	app.delete(
		"/v1/platform/admins/:id/sessions/:sessionId",
		{
			...route,
			schema: {
				...docs,
				summary:
					"End one of your own sessions; another admin's is refused (remove them to end all of theirs)",
				params: z.object({
					id: z.string().min(1).max(64),
					sessionId: z.string().uuid(),
				}),
				response: { 204: z.null(), ...errors },
			},
		},
		async (request, reply) => {
			try {
				await opts.admins.endSession(
					request.params.id,
					request.params.sessionId,
					request.platformAdmin!,
				);
				request.log.info(
					{ sessionId: request.params.sessionId },
					"platform admin session ended",
				);
				return reply.code(204).send(null);
			} catch (error) {
				return sendWriteError(reply, error);
			}
		},
	);

	app.post(
		"/v1/platform/admins",
		{
			...route,
			schema: {
				...docs,
				summary: "Add a platform admin; they can sign in at once",
				body: platformAdminInputSchema,
				response: { 201: adminSchema, ...errors },
			},
		},
		async (request, reply) => {
			try {
				const row = await opts.admins.add(request.body, request.platformAdmin!);
				request.log.info({ adminId: row.id }, "platform admin added");
				return reply.code(201).send(adminView(row));
			} catch (error) {
				return sendWriteError(reply, error);
			}
		},
	);

	app.delete(
		"/v1/platform/admins/:id",
		{
			...route,
			schema: {
				...docs,
				summary:
					"Remove a platform admin and end their sessions; never the last one, never yourself",
				params: z.object({ id: z.string().min(1).max(64) }),
				response: { 204: z.null(), ...errors },
			},
		},
		async (request, reply) => {
			try {
				await opts.admins.remove(request.params.id, request.platformAdmin!);
				request.log.info(
					{ adminId: request.params.id },
					"platform admin removed",
				);
				return reply.code(204).send(null);
			} catch (error) {
				return sendWriteError(reply, error);
			}
		},
	);

	app.get(
		"/v1/platform/admins/history",
		{
			...route,
			schema: {
				...docs,
				summary: `Every change to the platform admins, newest first, the latest ${HISTORY_LIMIT}`,
				response: {
					200: z.object({
						entries: z.array(
							z.object({
								id: z.string(),
								adminId: z.string(),
								address: z.string(),
								action: z.string(),
								actor: z.string(),
								createdAt: z.string(),
							}),
						),
					}),
					...errors,
				},
			},
		},
		async () => ({
			entries: (await opts.admins.history(HISTORY_LIMIT)).map((row) => ({
				id: row.id,
				adminId: row.adminId,
				address: row.address,
				action: row.action,
				actor: row.actor,
				createdAt: row.createdAt.toISOString(),
			})),
		}),
	);
}
