import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { hasZodFastifySchemaValidationErrors } from 'fastify-type-provider-zod';
import { BundlerRpcError } from '../services/bundler.js';

export class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export default fp(
  async (app: FastifyInstance) => {
    app.setErrorHandler((error, request, reply) => {
      if (hasZodFastifySchemaValidationErrors(error)) {
        return reply.code(400).send({
          error: 'validation',
          message: 'request does not match schema',
          issues: error.validation.map((issue) => ({
            path: issue.instancePath,
            message: issue.message,
          })),
        });
      }
      if (error instanceof ApiError) {
        return reply.code(error.statusCode).send({ error: error.code, message: error.message });
      }
      if (error instanceof BundlerRpcError) {
        return reply.code(502).send({ error: 'bundler', message: error.message, code: error.code });
      }
      const fastifyError = error as { statusCode?: number; code?: string; message?: string };
      if (typeof fastifyError.statusCode === 'number' && fastifyError.statusCode < 500) {
        return reply.code(fastifyError.statusCode).send({ error: fastifyError.code ?? 'request', message: fastifyError.message ?? 'request error' });
      }
      request.log.error({ err: error, tenant: request.tenant?.slug }, 'unhandled error');
      return reply.code(500).send({ error: 'internal', message: 'internal server error' });
    });
  },
  { name: 'error-handler' },
);
