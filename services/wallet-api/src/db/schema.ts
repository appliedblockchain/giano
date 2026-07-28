import { bigint, boolean, customType, index, jsonb, pgTable, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core';

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => 'bytea',
});

/** One row per tenant: tenant ≡ wallet origin ≡ RP ID (docs/MULTI-TENANCY-GAPS.md §5). */
export const tenants = pgTable('tenants', {
  id: uuid('id').primaryKey().defaultRandom(),
  slug: text('slug').notNull().unique(),
  walletOrigin: text('wallet_origin').notNull().unique(),
  /** IMMUTABLE once the tenant's first passkey exists — enforced by the seeder. */
  rpId: text('rp_id').notNull().unique(),
  rpName: text('rp_name').notNull(),
  expectedOrigins: text('expected_origins').array().notNull(),
  allowedDappOrigins: text('allowed_dapp_origins').array().notNull().default([]),
  corsOrigins: text('cors_origins').array().notNull().default([]),
  openRegistration: boolean('open_registration').notNull().default(false),
  /** Partial userop PolicyConfig overrides (bigints as decimal strings). */
  policy: jsonb('policy').notNull().default({}),
  branding: jsonb('branding').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const tenantAdminKeys = pgTable(
  'tenant_admin_keys',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    /** sha256 hex of the plaintext key; globally unique so key → tenant is unambiguous. */
    keyHash: text('key_hash').notNull().unique(),
    label: text('label'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('tenant_admin_keys_tenant_id_idx').on(t.tenantId)],
);

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    externalId: text('external_id').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  // C1: per-tenant uniqueness — two tenants picking 'user-1' must be two distinct users
  (t) => [unique('users_tenant_id_external_id_key').on(t.tenantId, t.externalId)],
);

export const credentials = pgTable(
  'credentials',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: text('credential_id').notNull(),
    /** The RP ID the credential was registered under (defence in depth for C2). */
    rpId: text('rp_id').notNull(),
    cosePublicKey: bytea('cose_public_key').notNull(),
    publicKeyX: text('public_key_x').notNull(),
    publicKeyY: text('public_key_y').notNull(),
    counter: bigint('counter', { mode: 'bigint' }).notNull().default(0n),
    transports: text('transports').array(),
    walletAddress: text('wallet_address').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    unique('credentials_tenant_id_credential_id_key').on(t.tenantId, t.credentialId),
    index('credentials_credential_id_idx').on(t.credentialId),
    index('credentials_user_id_idx').on(t.userId),
    index('credentials_wallet_address_idx').on(t.walletAddress),
  ],
);

export const challenges = pgTable(
  'challenges',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    // stays globally unique: 32 random bytes — tenant binding is enforced on consume()
    challenge: text('challenge').notNull().unique(),
    kind: text('kind', { enum: ['registration', 'authentication'] }).notNull(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
  },
  (t) => [index('challenges_expires_at_idx').on(t.expiresAt)],
);

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    // no tenant column: a session's tenant derives from its user's tenant_id
    // (users are created tenant-scoped and never move)
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: uuid('credential_id')
      .notNull()
      .references(() => credentials.id, { onDelete: 'cascade' }),
    // stays globally unique: bearer-token anti-collision IS the property we want
    tokenHash: text('token_hash').notNull().unique(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [index('sessions_user_id_idx').on(t.userId), index('sessions_expires_at_idx').on(t.expiresAt)],
);

export const useropLog = pgTable(
  'userop_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    // stays globally unique: a chain-level fact, and the constraint backs idempotency
    useropHash: text('userop_hash').notNull().unique(),
    sender: text('sender').notNull(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'set null' }),
    status: text('status', { enum: ['accepted', 'rejected', 'submitted', 'failed'] }).notNull(),
    policyResults: jsonb('policy_results').notNull().default([]),
    rejectReason: text('reject_reason'),
    bundlerResponse: jsonb('bundler_response'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('userop_log_sender_idx').on(t.sender), index('userop_log_tenant_id_created_at_idx').on(t.tenantId, t.createdAt)],
);

export const rorOrigins = pgTable(
  'ror_origins',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    origin: text('origin').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [unique('ror_origins_tenant_id_origin_key').on(t.tenantId, t.origin)],
);
