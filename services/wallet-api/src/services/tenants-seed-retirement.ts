import { eq, sql } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import { tenants } from '../db/schema.js';
import { appendTenantHistory, lockTenantWrites } from './tenants.js';

/**
 * ONE-TIME MIGRATION — remove once every deployment has booted this version.
 *
 * `TENANTS_SEED` is retired: tenants are managed only by Giano's platform admins, in the paymaster
 * console's Platform area. A database written by an earlier version still holds the seed's tenants
 * as `managed_by = 'seed'`, which the platform API would refuse to edit. This hands each of them to
 * the platform admins, exactly as a platform admin adopt would, with a history entry per tenant.
 *
 * Runs at every boot and does nothing once no seed-managed row is left — that check is what makes
 * it safe to keep in the image. Every replica runs it concurrently; the tenant-write lock makes the
 * second find nothing to do.
 */

export const SEED_RETIREMENT_ACTOR = 'system:tenants-seed-retirement';

export async function retireTenantsSeed(db: Db, log: { info: (message: string) => void; warn: (message: string) => void }): Promise<string[]> {
  if (process.env.TENANTS_SEED) {
    log.warn('TENANTS_SEED is set but no longer read: tenants are managed in the paymaster console\'s Platform area. Remove it from this deployment.');
  }
  const adopted = await db.transaction(async (tx) => {
    await lockTenantWrites(tx);
    const seeded = await tx.select().from(tenants).where(eq(tenants.managedBy, 'seed')).for('update');
    const slugs: string[] = [];
    for (const tenant of seeded) {
      const [after] = await tx
        .update(tenants)
        .set({ managedBy: 'operator', version: sql`${tenants.version} + 1`, updatedAt: sql`now()` })
        .where(eq(tenants.id, tenant.id))
        .returning();
      await appendTenantHistory(tx, { tenantId: tenant.id, action: 'adopt', actor: SEED_RETIREMENT_ACTOR, before: tenant, after });
      slugs.push(tenant.slug);
    }
    return slugs;
  });
  if (adopted.length > 0) {
    log.info(`TENANTS_SEED retirement: handed ${adopted.length} seed-managed tenant(s) to the platform admins: ${adopted.join(', ')}`);
  }
  return adopted;
}
