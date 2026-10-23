import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { tenantAdminKeys, tenants } from '../db/schema.js';
import { appendTenantHistory, checkOriginClaims, checkTenantInvariants, normaliseTenantFields, originClaims, sha256hex, tenantFieldsSchema } from './tenants.js';

/**
 * Test tenants for LOCAL stacks only — the dev, e2e and loopback compose files. A live deployment
 * (dev, staging, prod) never runs this: it boots with no tenants, and Giano's operators create
 * them in the paymaster console's Operator area.
 *
 * Loaded by the init step (src/init.ts) from TENANT_FIXTURES, and only for an environment marked
 * `localStack` (src/environments.ts), so no configuration of a live deployment can create a tenant.
 *
 * A fixture is a create and nothing else. A slug that already exists is left exactly as it is —
 * once created, a fixture tenant is an ordinary operator-managed tenant, so a restart never
 * reverts an edit made in the console. `down -v` is what puts a fixture back to its committed
 * values.
 *
 * Fixtures differ from an operator create in two ways, both for the sake of reproducible local
 * stacks: the id can be pinned (the devnet paymaster is pre-registered against fixed tenant ids),
 * and the admin keys are given in plaintext (the provisioners and the e2e suite authenticate with
 * fixed keys). Everything else goes through the same validation and origin-claim checks as every
 * other tenant write.
 */

export const FIXTURE_ACTOR = 'fixture';

export const tenantFixtureSchema = tenantFieldsSchema
  .extend({
    /** Plaintext admin keys — stored sha256-hashed, never persisted or logged as-is. */
    adminKeys: z.array(z.string().min(16, 'admin keys must be at least 16 characters')).default([]),
  })
  .superRefine((fixture, ctx) => {
    for (const issue of checkTenantInvariants(fixture, { adminKeyCount: fixture.adminKeys.length })) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: issue.path, message: issue.message });
    }
  })
  .transform(normaliseTenantFields);

export type TenantFixture = z.infer<typeof tenantFixtureSchema>;

export const tenantFixturesSchema = z.array(tenantFixtureSchema).superRefine((fixtures, ctx) => {
  const duplicate = (values: string[], what: string) => {
    const seen = new Set<string>();
    for (const value of values) {
      if (seen.has(value)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: `duplicate ${what} across tenants: ${value}` });
      seen.add(value);
    }
  };
  duplicate(fixtures.map((f) => f.slug), 'slug');
  duplicate(fixtures.map((f) => f.id).filter((id): id is string => Boolean(id)), 'id');
  duplicate(fixtures.map((f) => f.walletOrigin), 'walletOrigin');
  duplicate(fixtures.map((f) => f.rpId), 'rpId');
  // a plaintext key shared by two tenants would make key → tenant resolution ambiguous
  duplicate(fixtures.flatMap((f) => f.adminKeys), 'admin key');
  // the database check would catch this too, but only after the first entry had been written
  const claimedBy = new Map<string, string>();
  for (const fixture of fixtures) {
    for (const origin of originClaims(fixture)) {
      const other = claimedBy.get(origin);
      if (other !== undefined && other !== fixture.slug) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `origin ${origin} is claimed by both "${other}" and "${fixture.slug}" — no origin may resolve to two tenants` });
      } else {
        claimedBy.set(origin, fixture.slug);
      }
    }
  }
});

/** Parses a JSON array of fixtures; throws with readable messages. */
export function parseTenantFixtures(raw: string): TenantFixture[] {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (error) {
    throw new Error(`tenant fixtures are not valid JSON: ${(error as Error).message}`);
  }
  const parsed = tenantFixturesSchema.safeParse(json);
  if (!parsed.success) {
    const details = parsed.error.issues.map((issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`).join('\n');
    throw new Error(`invalid tenant fixtures:\n${details}`);
  }
  return parsed.data;
}

/**
 * Creates every fixture whose slug does not exist yet, each in its own transaction under the
 * tenant-write lock. Returns which were created and which were already there.
 */
export async function loadTenantFixtures(db: Db, fixtures: TenantFixture[]): Promise<{ created: string[]; existing: string[] }> {
  const created: string[] = [];
  const existing: string[] = [];
  for (const fixture of fixtures) {
    await db.transaction(async (tx) => {
      // takes the tenant-write lock before the existence check, so two loaders cannot both insert
      const clash = await checkOriginClaims(tx, { selfId: null, claims: originClaims(fixture) });
      const [stored] = await tx.select({ id: tenants.id }).from(tenants).where(eq(tenants.slug, fixture.slug));
      if (stored) {
        existing.push(fixture.slug);
        return;
      }
      if (clash) {
        throw new Error(`tenant "${fixture.slug}": origin ${clash.origin} is already claimed by tenant "${clash.slug}" (${clash.status}) — no origin may resolve to two tenants`);
      }
      const { adminKeys, id, ...fields } = fixture;
      const [tenant] = await tx
        .insert(tenants)
        .values({ ...fields, ...(id ? { id } : {}), managedBy: 'operator' })
        .returning();
      const hashes = [...new Set(adminKeys.map(sha256hex))];
      if (hashes.length > 0) {
        await tx.insert(tenantAdminKeys).values(hashes.map((keyHash) => ({ tenantId: tenant.id, keyHash, label: 'fixture', createdBy: FIXTURE_ACTOR })));
      }
      await appendTenantHistory(tx, { tenantId: tenant.id, action: 'create', actor: FIXTURE_ACTOR, before: null, after: tenant });
      created.push(fixture.slug);
    });
  }
  return { created, existing };
}
