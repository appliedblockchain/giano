import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { AppConfig } from '../config.js';
import { operatorInputSchema, type Operator, type OperatorService } from '../services/operators.js';
import { TenantWriteError } from '../services/tenants.js';

const HISTORY_LIMIT = 100;

const errorSchema = z.object({ error: z.string(), message: z.string() }).passthrough();
const errors = { 400: errorSchema, 401: errorSchema, 404: errorSchema, 409: errorSchema };

const operatorSchema = z.object({ id: z.string(), address: z.string(), addedBy: z.string(), createdAt: z.string() });
const operatorView = (row: Operator) => ({ id: row.id, address: row.address, addedBy: row.addedBy, createdAt: row.createdAt.toISOString() });

function sendWriteError(reply: FastifyReply, error: unknown) {
  if (!(error instanceof TenantWriteError)) throw error;
  return reply.code(error.status).send({ error: error.code, message: error.message, ...error.detail });
}

/**
 * The operators themselves (specs/OPERATOR-ADMIN-SPECS.md §4.1): list, add, remove and history.
 * Registered with the rest of the operator tier. Every route needs an operator session, refuses an
 * Origin, and is rate limited per session. Removing the last operator, or yourself, is refused.
 */
export default async function operatorOperatorRoutes(instance: FastifyInstance, opts: { operators: OperatorService; config: AppConfig }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  app.addHook('onRequest', app.requireOperator);

  const route = {
    config: {
      rateLimit: {
        max: opts.config.OPERATOR_RATE_LIMIT_PER_MINUTE,
        timeWindow: '1 minute',
        keyGenerator: (request: FastifyRequest) => `operator-session:${request.operator?.sessionId ?? 'none'}`,
      },
    },
  };
  const docs = { tags: ['operator'], security: [{ operatorSession: [] }] };

  app.get(
    '/v1/operator/operators',
    { ...route, schema: { ...docs, summary: 'The operators, oldest first', response: { 200: z.object({ operators: z.array(operatorSchema) }), ...errors } } },
    async () => ({ operators: (await opts.operators.list()).map(operatorView) }),
  );

  app.post(
    '/v1/operator/operators',
    {
      ...route,
      schema: { ...docs, summary: 'Add an operator; they can sign in at once', body: operatorInputSchema, response: { 201: operatorSchema, ...errors } },
    },
    async (request, reply) => {
      try {
        const row = await opts.operators.add(request.body, request.operator!);
        request.log.info({ operatorId: row.id }, 'operator added');
        return reply.code(201).send(operatorView(row));
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.delete(
    '/v1/operator/operators/:id',
    {
      ...route,
      schema: {
        ...docs,
        summary: 'Remove an operator and end their sessions; never the last one, never yourself',
        params: z.object({ id: z.string().min(1).max(64) }),
        response: { 204: z.null(), ...errors },
      },
    },
    async (request, reply) => {
      try {
        await opts.operators.remove(request.params.id, request.operator!);
        request.log.info({ operatorId: request.params.id }, 'operator removed');
        return reply.code(204).send(null);
      } catch (error) {
        return sendWriteError(reply, error);
      }
    },
  );

  app.get(
    '/v1/operator/operators/history',
    {
      ...route,
      schema: {
        ...docs,
        summary: `Every change to the operators, newest first, the latest ${HISTORY_LIMIT}`,
        response: {
          200: z.object({
            entries: z.array(z.object({ id: z.string(), operatorId: z.string(), address: z.string(), action: z.string(), actor: z.string(), createdAt: z.string() })),
          }),
          ...errors,
        },
      },
    },
    async () => ({
      entries: (await opts.operators.history(HISTORY_LIMIT)).map((row) => ({
        id: row.id,
        operatorId: row.operatorId,
        address: row.address,
        action: row.action,
        actor: row.actor,
        createdAt: row.createdAt.toISOString(),
      })),
    }),
  );
}
