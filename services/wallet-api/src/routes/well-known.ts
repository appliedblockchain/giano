import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { rorOrigins } from '../db/schema.js';

/**
 * Related Origin Requests (ROR): served under the wallet origin so passkeys bound to
 * the wallet RP ID can be exercised from the registered related origins.
 * https://passkeys.dev/docs/advanced/related-origins/
 */
export default async function wellKnownRoutes(
  instance: FastifyInstance, opts: { db: Db }) {
  const app = instance.withTypeProvider<ZodTypeProvider>();
  app.get(
    '/.well-known/webauthn',
    { schema: { tags: ['well-known'], response: { 200: z.object({ origins: z.array(z.string()) }) } } },
    async () => {
      const rows = await opts.db.select({ origin: rorOrigins.origin }).from(rorOrigins);
      return { origins: rows.map((r) => r.origin) };
    },
  );
}
