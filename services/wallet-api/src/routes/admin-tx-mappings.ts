import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { sha256hex } from '../services/tenants.js';
import { checkMapping, createTxMappingService, MAX_MAPPING_BYTES, normaliseContract } from '../services/tx-mappings.js';

/**
 * A tenant's transaction display mappings: the ERC-7730 descriptors that let the wallet explain
 * calls to its contracts. Scoped to the tenant whose admin key authorised the request, per
 * chain (MC-53 for chain selection), one mapping per contract, full-replace on write.
 *
 * Another tenant's mapping is indistinguishable from a missing one (404, never 403).
 */
export default async function adminTxMappingRoutes(instance: FastifyInstance, opts: { db: Db }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  app.addHook('preHandler', app.requireAdmin);
  app.addHook('preHandler', app.requireChain);

  const mappings = createTxMappingService(opts.db);

  const chainQuery = z.object({ chainId: z.coerce.number().int().positive().optional() });
  const contractParam = z.object({ contract: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 20-byte hex address') });
  const issue = z.object({ path: z.string(), message: z.string() });
  const errorBody = z.object({ error: z.string(), message: z.string() });
  const validationBody = errorBody.extend({ issues: z.array(issue) });
  const mappingBody = z.object({
    id: z.string(),
    contract: z.string(),
    descriptor: z.unknown(),
    updatedAt: z.string(),
    /** False when the stored descriptor no longer passes validation; it is then not served. */
    valid: z.boolean(),
    issues: z.array(issue),
  });

  const keyHashOf = (request: { headers: { authorization?: string } }) => {
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ')) return null;
    return sha256hex(header.slice('Bearer '.length).trim());
  };

  const present = (row: Awaited<ReturnType<typeof mappings.get>> & object) => ({
    id: row.id,
    contract: row.contract,
    descriptor: row.descriptor,
    updatedAt: row.updatedAt.toISOString(),
    valid: row.valid,
    issues: row.issues,
  });

  app.get(
    '/v1/admin/tx-mappings',
    {
      schema: {
        tags: ['admin'],
        summary: "This tenant's transaction display mappings for one chain",
        security: [{ adminKey: [] }],
        querystring: chainQuery,
        response: { 200: z.object({ chainId: z.number(), mappings: z.array(mappingBody) }) },
      },
    },
    async (request) => {
      const chainId = request.chain!.chainId;
      const rows = await mappings.list(request.adminTenant!.id, chainId);
      return { chainId, mappings: rows.map(present) };
    },
  );

  app.get(
    '/v1/admin/tx-mappings/history',
    {
      schema: {
        tags: ['admin'],
        summary: 'Who changed the transaction display mappings, and when',
        security: [{ adminKey: [] }],
        querystring: chainQuery.extend({ limit: z.coerce.number().int().min(1).max(200).default(50) }),
        response: {
          200: z.object({
            revisions: z.array(
              z.object({
                id: z.string(),
                contract: z.string(),
                action: z.enum(['put', 'delete']),
                descriptor: z.unknown().nullable(),
                createdAt: z.string(),
                /** The admin key's hash, not the key: enough to tell two writers apart. */
                createdByKeyHash: z.string().nullable(),
              }),
            ),
          }),
        },
      },
    },
    async (request) => {
      const rows = await mappings.history(request.adminTenant!.id, request.chain!.chainId, request.query.limit);
      return {
        revisions: rows.map((row) => ({
          id: row.id,
          contract: row.contract,
          action: row.action as 'put' | 'delete',
          descriptor: row.descriptor ?? null,
          createdAt: row.createdAt.toISOString(),
          createdByKeyHash: row.createdByKeyHash,
        })),
      };
    },
  );

  app.get(
    '/v1/admin/tx-mappings/:contract',
    {
      schema: {
        tags: ['admin'],
        summary: 'One mapping, by contract',
        security: [{ adminKey: [] }],
        params: contractParam,
        querystring: chainQuery,
        response: { 200: mappingBody, 404: errorBody },
      },
    },
    async (request, reply) => {
      const contract = normaliseContract(request.params.contract)!;
      const row = await mappings.get(request.adminTenant!.id, request.chain!.chainId, contract);
      if (!row) return reply.code(404).send({ error: 'not-found', message: 'mapping not found' });
      return present(row);
    },
  );

  app.put(
    '/v1/admin/tx-mappings/:contract',
    {
      bodyLimit: MAX_MAPPING_BYTES,
      schema: {
        tags: ['admin'],
        summary: 'Create or replace the mapping for a contract (for one chain)',
        description:
          'The body is an ERC-7730 descriptor with an inline ABI. Validated on write with one issue per ' +
          'violation, each with its JSON path; nothing is stored unless every check passes. The descriptor ' +
          'must bind the requested chain and contract in context.contract.deployments. Bodies over 64 KiB are refused.',
        security: [{ adminKey: [] }],
        params: contractParam,
        querystring: chainQuery,
        body: z.unknown(),
        response: { 200: mappingBody, 400: validationBody },
      },
    },
    async (request, reply) => {
      const tenant = request.adminTenant!;
      const chainId = request.chain!.chainId;
      const contract = normaliseContract(request.params.contract)!;

      const check = checkMapping(request.body, chainId, contract);
      if (!check.ok) {
        return reply.code(400).send({ error: 'validation', message: 'transaction mapping is not valid', issues: check.issues });
      }

      const row = await mappings.put(tenant.id, chainId, contract, check.descriptor, keyHashOf(request));
      request.log.info({ txMappings: 'put', chainId, contract }, 'transaction mapping written');
      return present(row);
    },
  );

  app.delete(
    '/v1/admin/tx-mappings/:contract',
    {
      schema: {
        tags: ['admin'],
        summary: 'Remove the mapping for a contract (for one chain)',
        security: [{ adminKey: [] }],
        params: contractParam,
        querystring: chainQuery,
        response: { 204: z.null(), 404: errorBody },
      },
    },
    async (request, reply) => {
      const contract = normaliseContract(request.params.contract)!;
      const removed = await mappings.remove(request.adminTenant!.id, request.chain!.chainId, contract, keyHashOf(request));
      if (!removed) return reply.code(404).send({ error: 'not-found', message: 'mapping not found' });
      request.log.info({ txMappings: 'delete', chainId: request.chain!.chainId, contract }, 'transaction mapping removed');
      return reply.code(204).send(null);
    },
  );
}
