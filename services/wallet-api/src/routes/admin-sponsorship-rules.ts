import type { FastifyInstance, FastifyReply } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Db } from "../db/index.js";
import { requireAdminTenantOf } from "../plugins/auth.js";
import { requireChainOf } from "../plugins/chain.js";
import {
	formatConfigIssues,
	ruleCreateSchema,
	rulePatchSchema,
} from "../services/sponsorship-config.js";
import {
	BadCursorError,
	createRule,
	deleteRule,
	getRule,
	listRuleEvents,
	listRules,
	patchRule,
	RuleWriteError,
	ruleView,
} from "../services/sponsorship-rule-store.js";
import { sha256hex } from "../services/tenants.js";

/**
 * A tenant's sponsorship rules, one record each (openspec sponsorship-rules-api).
 *
 * A tenant that deploys a contract for every payment adds one rule per contract, before the
 * deployment when the address is predictable, without reading or rewriting its other rules. A
 * `clientReference` makes a retried create safe, and an `expiresAt` keeps rules from piling up.
 * The settings (`enabled`, the caps) stay on `/v1/admin/sponsorship`.
 */
export default async function adminSponsorshipRulesRoutes(
	instance: FastifyInstance,
	opts: { db: Db; config: AppConfig },
) {
	const app = instance.withTypeProvider<ZodTypeProvider>();
	app.addHook("preHandler", app.requireAdmin);
	app.addHook("preHandler", app.requireChain);

	const { db, config } = opts;
	const maxRules = config.SPONSORSHIP_MAX_RULES_PER_CHAIN;

	const keyHashOf = (request: { headers: { authorization?: string } }) => {
		const header = request.headers.authorization;
		if (!header?.startsWith("Bearer ")) return null;
		return sha256hex(header.slice("Bearer ".length).trim());
	};

	const chainQuery = z.object({
		chainId: z.coerce.number().int().positive().optional(),
	});
	const idParams = z.object({ id: z.string().uuid() });
	const ruleSchema = z.object({
		id: z.string(),
		contract: z.string(),
		functions: z.union([z.literal("all"), z.array(z.string())]),
		clientReference: z.string().nullable(),
		expiresAt: z.string().nullable(),
		createdAt: z.string(),
		updatedAt: z.string(),
	});
	const errorSchema = z.object({
		error: z.string(),
		message: z.string(),
		issues: z
			.array(z.object({ path: z.string(), message: z.string() }))
			.optional(),
		rule: ruleSchema.optional(),
	});
	const docs = {
		tags: ["admin"],
		security: [{ adminKey: [] }],
	};

	const notFound = (reply: FastifyReply) =>
		reply.code(404).send({
			error: "not-found",
			message: "this tenant has no such rule on this chain",
		});

	const invalid = (
		reply: FastifyReply,
		issues: Array<{ path: string; message: string }>,
	) =>
		reply.code(400).send({
			error: "validation",
			message: "the rule is not valid",
			issues,
		});

	const refused = (reply: FastifyReply, error: unknown) => {
		if (!(error instanceof RuleWriteError)) throw error;
		return reply.code(409).send({
			error: error.code,
			message: error.message,
			...(error.rule ? { rule: ruleView(error.rule) } : {}),
		});
	};

	app.post(
		"/v1/admin/sponsorship/rules",
		{
			schema: {
				...docs,
				summary: "Allow one contract for sponsorship (for one chain)",
				description:
					"Creates one rule without touching the tenant's other rules. A create that repeats a clientReference " +
					"returns the existing rule (200) when it describes the same rule, and 409 client-reference-conflict when it " +
					"does not. A contract can have one active rule (409 duplicate-contract), and a tenant at most " +
					"SPONSORSHIP_MAX_RULES_PER_CHAIN active rules per chain (409 rule-limit-reached). For a contract the tenant " +
					"will deploy at a predictable address, create the rule before the deployment.",
				querystring: chainQuery,
				body: z.unknown(),
				response: {
					200: ruleSchema,
					201: ruleSchema,
					400: errorSchema,
					409: errorSchema,
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const parsed = ruleCreateSchema.safeParse(request.body);
			if (!parsed.success)
				return invalid(reply, formatConfigIssues(parsed.error));
			const now = new Date();
			if (parsed.data.expiresAt && parsed.data.expiresAt <= now)
				return invalid(reply, [
					{ path: "expiresAt", message: "must be in the future" },
				]);
			try {
				const { created, rule } = await createRule(db, {
					tenantId: tenant.id,
					chainId,
					input: parsed.data,
					keyHash: keyHashOf(request),
					now,
					maxRules,
				});
				request.log.info(
					{ sponsorship: "rule-created", ruleId: rule.id, created, chainId },
					"sponsorship rule created",
				);
				return reply.code(created ? 201 : 200).send(ruleView(rule));
			} catch (error) {
				return refused(reply, error);
			}
		},
	);

	app.get(
		"/v1/admin/sponsorship/rules",
		{
			schema: {
				...docs,
				summary: "List this tenant's sponsorship rules (for one chain)",
				description:
					"Newest first, a page at a time: pass nextCursor back as cursor. Only active rules unless includeExpired=true.",
				querystring: chainQuery.extend({
					contract: z.string().optional(),
					clientReference: z.string().optional(),
					includeExpired: z
						.enum(["true", "false"])
						.optional()
						.transform((value) => value === "true"),
					limit: z.coerce.number().int().min(1).max(500).default(100),
					cursor: z.string().optional(),
				}),
				response: {
					200: z.object({
						rules: z.array(ruleSchema),
						nextCursor: z.string().nullable(),
					}),
					400: errorSchema,
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			try {
				const page = await listRules(db, {
					tenantId: tenant.id,
					chainId,
					now: new Date(),
					contract: request.query.contract,
					clientReference: request.query.clientReference,
					includeExpired: request.query.includeExpired,
					limit: request.query.limit,
					cursor: request.query.cursor,
				});
				return {
					rules: page.rules.map(ruleView),
					nextCursor: page.nextCursor,
				};
			} catch (error) {
				if (!(error instanceof BadCursorError)) throw error;
				return reply.code(400).send({
					error: "validation",
					message: "cursor is not one this API returned",
				});
			}
		},
	);

	app.get(
		"/v1/admin/sponsorship/rules/events",
		{
			schema: {
				...docs,
				summary: "Who created, changed or removed which rule, and when",
				description:
					"Newest first, a page at a time. createdByKeyHash is the sha256 of the admin key, or null when " +
					"wallet-api made the change itself (a migration, or removing an expired rule).",
				querystring: chainQuery.extend({
					limit: z.coerce.number().int().min(1).max(500).default(100),
					cursor: z.string().optional(),
				}),
				response: {
					200: z.object({
						events: z.array(
							z.object({
								id: z.string(),
								ruleId: z.string(),
								action: z.string(),
								rule: z.unknown(),
								createdAt: z.string(),
								createdByKeyHash: z.string().nullable(),
							}),
						),
						nextCursor: z.string().nullable(),
					}),
					400: errorSchema,
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			try {
				const page = await listRuleEvents(db, {
					tenantId: tenant.id,
					chainId,
					limit: request.query.limit,
					cursor: request.query.cursor,
				});
				return {
					events: page.events.map((event) => ({
						id: event.id,
						ruleId: event.ruleId,
						action: event.action,
						rule: event.rule,
						createdAt: event.createdAt.toISOString(),
						createdByKeyHash: event.createdByKeyHash,
					})),
					nextCursor: page.nextCursor,
				};
			} catch (error) {
				if (!(error instanceof BadCursorError)) throw error;
				return reply.code(400).send({
					error: "validation",
					message: "cursor is not one this API returned",
				});
			}
		},
	);

	app.get(
		"/v1/admin/sponsorship/rules/:id",
		{
			schema: {
				...docs,
				summary: "Read one sponsorship rule",
				querystring: chainQuery,
				params: idParams,
				response: { 200: ruleSchema, 404: errorSchema },
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const rule = await getRule(db, {
				tenantId: tenant.id,
				chainId,
				id: request.params.id,
			});
			return rule ? ruleView(rule) : notFound(reply);
		},
	);

	app.patch(
		"/v1/admin/sponsorship/rules/:id",
		{
			schema: {
				...docs,
				summary: "Change a rule's functions or expiry",
				description:
					"Only functions and expiresAt can change; expiresAt: null removes the expiry. The contract and the " +
					"clientReference name what the rule is for, so a body that names either is refused.",
				querystring: chainQuery,
				params: idParams,
				body: z.unknown(),
				response: {
					200: ruleSchema,
					400: errorSchema,
					404: errorSchema,
					409: errorSchema,
				},
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const body = request.body;
			if (body && typeof body === "object") {
				const fixed = ["contract", "clientReference"].filter((key) =>
					Object.hasOwn(body, key),
				);
				if (fixed.length > 0)
					return invalid(
						reply,
						fixed.map((path) => ({
							path,
							message:
								"cannot change; a rule for another contract or reference is a new rule",
						})),
					);
			}
			const parsed = rulePatchSchema.safeParse(body);
			if (!parsed.success)
				return invalid(reply, formatConfigIssues(parsed.error));
			const now = new Date();
			if (parsed.data.expiresAt && parsed.data.expiresAt <= now)
				return invalid(reply, [
					{ path: "expiresAt", message: "must be in the future, or null" },
				]);
			try {
				const rule = await patchRule(db, {
					tenantId: tenant.id,
					chainId,
					id: request.params.id,
					patch: parsed.data,
					keyHash: keyHashOf(request),
					now,
					maxRules,
				});
				return rule ? ruleView(rule) : notFound(reply);
			} catch (error) {
				return refused(reply, error);
			}
		},
	);

	app.delete(
		"/v1/admin/sponsorship/rules/:id",
		{
			schema: {
				...docs,
				summary: "Remove a sponsorship rule",
				querystring: chainQuery,
				params: idParams,
				response: { 204: z.null(), 404: errorSchema },
			},
		},
		async (request, reply) => {
			const tenant = requireAdminTenantOf(request);
			const chainId = requireChainOf(request).chainId;
			const removed = await deleteRule(db, {
				tenantId: tenant.id,
				chainId,
				id: request.params.id,
				keyHash: keyHashOf(request),
			});
			return removed ? reply.code(204).send(null) : notFound(reply);
		},
	);
}
