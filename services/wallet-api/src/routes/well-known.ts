import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { rorOrigins } from '../db/schema.js';

/**
 * Related Origin Requests (ROR): served under the wallet origin so passkeys bound to
 * the wallet RP ID can be exercised from the registered related origins.
 * https://passkeys.dev/docs/advanced/related-origins/
 *
 * Resolution is by Host header (browsers fetch this same-origin, so no Origin header
 * is sent): each tenant's document contains only its own origins; an unknown host is
 * a plain 404 so probing the raw API host enumerates nothing.
 */
export default async function wellKnownRoutes(
  instance: FastifyInstance, opts: { db: Db }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  app.get(
    '/.well-known/webauthn',
    {
      preHandler: app.requireTenantByHost,
      schema: { tags: ['well-known'], response: { 200: z.object({ origins: z.array(z.string()) }), 404: z.object({ error: z.string(), message: z.string() }) } },
    },
    async (request) => {
      const rows = await opts.db.select({ origin: rorOrigins.origin }).from(rorOrigins).where(eq(rorOrigins.tenantId, request.tenant!.id));
      return { origins: rows.map((r) => r.origin) };
    },
  );
}
