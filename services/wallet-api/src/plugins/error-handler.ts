import type { FastifyInstance } from "fastify";
import fp from "fastify-plugin";
import { hasZodFastifySchemaValidationErrors } from "fastify-type-provider-zod";
import { BundlerRpcError } from "../services/bundler.js";
import { UpstreamLimitError } from "../services/upstream-fetch.js";

export class ApiError extends Error {
	constructor(
		public readonly statusCode: number,
		public readonly code: string,
		message: string,
	) {
		super(message);
		this.name = "ApiError";
	}
}

export default fp(
	async (app: FastifyInstance) => {
		app.setErrorHandler((error, request, reply) => {
			if (hasZodFastifySchemaValidationErrors(error)) {
				return reply.code(400).send({
					error: "validation",
					message: "request does not match schema",
					issues: error.validation.map((issue) => ({
						path: issue.instancePath,
						message: issue.message,
					})),
				});
			}
			if (error instanceof ApiError) {
				return reply
					.code(error.statusCode)
					.send({ error: error.code, message: error.message });
			}
			if (error instanceof BundlerRpcError) {
				return reply
					.code(502)
					.send({ error: "bundler", message: error.message, code: error.code });
			}
			// G37: a bundler or node call past its time or size limit. 504 for time, 502 for size.
			// Either way the upstream gave no usable answer, and the message names no URL.
			if (error instanceof UpstreamLimitError) {
				request.log.warn(
					{ reason: error.reason, upstream: error.upstream },
					"upstream call hit its limit",
				);
				return error.reason === "timeout"
					? reply
							.code(504)
							.send({ error: "upstream-timeout", message: error.message })
					: reply.code(502).send({
							error: "upstream-response-too-large",
							message: error.message,
						});
			}
			const fastifyError = error as {
				statusCode?: number;
				code?: string;
				message?: string;
			};
			if (
				typeof fastifyError.statusCode === "number" &&
				fastifyError.statusCode < 500
			) {
				return reply.code(fastifyError.statusCode).send({
					error: fastifyError.code ?? "request",
					message: fastifyError.message ?? "request error",
				});
			}
			request.log.error(
				{ err: error, tenant: request.tenant?.slug },
				"unhandled error",
			);
			return reply
				.code(500)
				.send({ error: "internal", message: "internal server error" });
		});
	},
	{ name: "error-handler" },
);
