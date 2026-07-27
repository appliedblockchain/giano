import { bigint, customType, index, jsonb, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => 'bytea',
});

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  externalId: text('external_id').notNull().unique(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const credentials = pgTable(
  'credentials',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: text('credential_id').notNull().unique(),
    cosePublicKey: bytea('cose_public_key').notNull(),
    publicKeyX: text('public_key_x').notNull(),
    publicKeyY: text('public_key_y').notNull(),
    counter: bigint('counter', { mode: 'bigint' }).notNull().default(0n),
    transports: text('transports').array(),
    walletAddress: text('wallet_address').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('credentials_user_id_idx').on(t.userId), index('credentials_wallet_address_idx').on(t.walletAddress)],
);

export const challenges = pgTable(
  'challenges',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    challenge: text('challenge').notNull().unique(),
    kind: text('kind', { enum: ['registration', 'authentication'] }).notNull(),
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
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: uuid('credential_id')
      .notNull()
      .references(() => credentials.id, { onDelete: 'cascade' }),
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
    useropHash: text('userop_hash').notNull().unique(),
    sender: text('sender').notNull(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'set null' }),
    status: text('status', { enum: ['accepted', 'rejected', 'submitted', 'failed'] }).notNull(),
    policyResults: jsonb('policy_results').notNull().default([]),
    rejectReason: text('reject_reason'),
    bundlerResponse: jsonb('bundler_response'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('userop_log_sender_idx').on(t.sender)],
);

export const rorOrigins = pgTable('ror_origins', {
  id: uuid('id').primaryKey().defaultRandom(),
  origin: text('origin').notNull().unique(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
