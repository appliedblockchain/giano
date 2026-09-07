import { bigint, boolean, customType, index, jsonb, numeric, pgTable, primaryKey, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core';

const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => 'bytea',
});

/** One row per tenant: tenant ≡ wallet origin ≡ RP ID (specs/DEVELOPER-GUIDE.md §1). */
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
    /** User-set label (WM-07). Never an input to authorisation or matching (WM-11). */
    name: text('name'),
    /**
     * Set once the owner key was verified removed on-chain (WM-31). The row is kept so the
     * interface can show the credential honestly as "no longer an owner" (WM-04); a removed
     * credential can no longer authenticate or hold sessions.
     */
    removedAt: timestamp('removed_at', { withTimezone: true }),
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
    /**
     * The wallet this session is scoped to (WM-33/D3), captured at issue time from the
     * authenticating credential. The relay's sender-binding rule reads THIS, so any owner
     * credential of a wallet opens a session that can act for it — no relay exception (WM-34).
     */
    walletAddress: text('wallet_address').notNull(),
    // stays globally unique: bearer-token anti-collision IS the property we want
    tokenHash: text('token_hash').notNull().unique(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [
    index('sessions_user_id_idx').on(t.userId),
    index('sessions_expires_at_idx').on(t.expiresAt),
    index('sessions_credential_id_idx').on(t.credentialId),
  ],
);

/**
 * A pending addition (D8): the slot a second device deposits a newly created public key
 * into. Opened by the AUTHORISING device — tenant, user and target wallet come from its
 * authenticated session (WM-19) — routed to by a short single-use claim code, and inert
 * until an existing credential signs the on-chain addition. Chain writes first; the
 * registry binds only at consumption (WM-15), so the registry never claims an owner the
 * chain does not have.
 */
export const pendingAdditions = pgTable(
  'pending_additions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    walletAddress: text('wallet_address').notNull(),
    claimCode: text('claim_code').notNull().unique(),
    status: text('status', { enum: ['open', 'filled', 'consumed', 'declined', 'expired'] })
      .notNull()
      .default('open'),
    credentialId: text('credential_id'),
    cosePublicKey: bytea('cose_public_key'),
    publicKeyX: text('public_key_x'),
    publicKeyY: text('public_key_y'),
    transports: text('transports').array(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    filledAt: timestamp('filled_at', { withTimezone: true }),
    consumedAt: timestamp('consumed_at', { withTimezone: true }),
  },
  (t) => [index('pending_additions_user_id_idx').on(t.userId), index('pending_additions_expires_at_idx').on(t.expiresAt)],
);

/** Durable audit of every attempted owner-set change and pending-addition transition (WM-50, WM-51). */
export const walletManagementLog = pgTable(
  'wallet_management_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'set null' }),
    walletAddress: text('wallet_address').notNull(),
    action: text('action').notNull(),
    outcome: text('outcome', { enum: ['ok', 'refused'] }).notNull(),
    detail: jsonb('detail').notNull().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('wallet_management_log_wallet_idx').on(t.walletAddress, t.createdAt),
    index('wallet_management_log_tenant_idx').on(t.tenantId, t.createdAt),
  ],
);

export const useropLog = pgTable(
  'userop_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    // stays globally unique: the hash commits to the chain id, so two chains cannot
    // collide, and the constraint continues to back relay idempotency
    useropHash: text('userop_hash').notNull().unique(),
    /** Which chain the operation went to — answerable directly, never by inference (MC-59). */
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
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
    /** Links a relayed op to the sponsorship decision that authorised it — one join from
     *  "we relayed this" to "why was it sponsored and what was it charged". */
    sponsorshipDecisionId: uuid('sponsorship_decision_id'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('userop_log_sender_idx').on(t.sender),
    index('userop_log_tenant_id_created_at_idx').on(t.tenantId, t.createdAt),
    index('userop_log_chain_id_created_at_idx').on(t.chainId, t.createdAt),
  ],
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

// ── Sponsorship ────────────────────────────────────────────────────────────────
//
// A tenant's sponsorship *rules* are its own to edit through its admin key, and live in their
// own table so TENANTS_SEED keeps its declarative meaning — a restart must never revert a
// tenant's edit. A tenant with no row sponsors nothing, which is deny-by-default in the storage
// layer as well as in the rules engine.
//
// A tenant's *balance* is not the service's to own: it is chain state, cached here from paymaster
// events and reconciled against the deposit. Reservations are the one thing the service owns
// outright, and they are what makes per-tenant segregation hold when several of a tenant's
// operations are authorised concurrently.

export const tenantSponsorship = pgTable(
  'tenant_sponsorship',
  {
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
    /** Validated by the zod schema in services/sponsorship-config.ts on every write. */
    config: jsonb('config').notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    /** sha256 of the admin key that wrote it — who changed the rules, without storing the key. */
    updatedByKeyHash: text('updated_by_key_hash'),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.chainId] })],
);

export const tenantSponsorshipHistory = pgTable(
  'tenant_sponsorship_history',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
    config: jsonb('config').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    createdByKeyHash: text('created_by_key_hash'),
  },
  (t) => [index('tenant_sponsorship_history_tenant_idx').on(t.tenantId, t.createdAt)],
);

/** Cache of on-chain per-tenant balances. Rebuilt from events; never the authority. */
export const paymasterTenants = pgTable(
  'paymaster_tenants',
  {
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
    paymasterAddress: text('paymaster_address').notNull(),
    /** wei, as a numeric string — bigints do not survive JSON or a JS number. */
    balanceWei: numeric('balance_wei', { precision: 78, scale: 0 }).notNull().default('0'),
    deficitWei: numeric('deficit_wei', { precision: 78, scale: 0 }).notNull().default('0'),
    withdrawAddress: text('withdraw_address'),
    lastSyncedBlock: bigint('last_synced_block', { mode: 'bigint' }),
    lastSyncedAt: timestamp('last_synced_at', { withTimezone: true }),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.chainId] })],
);

export const sponsorshipReservations = pgTable(
  'sponsorship_reservations',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
    sender: text('sender').notNull(),
    nonce: numeric('nonce', { precision: 78, scale: 0 }).notNull(),
    useropHash: text('userop_hash'),
    maxCostWei: numeric('max_cost_wei', { precision: 78, scale: 0 }).notNull(),
    feeWei: numeric('fee_wei', { precision: 78, scale: 0 }).notNull(),
    overheadWei: numeric('overhead_wei', { precision: 78, scale: 0 }).notNull(),
    totalWei: numeric('total_wei', { precision: 78, scale: 0 }).notNull(),
    state: text('state', { enum: ['reserved', 'settled', 'expired', 'released'] }).notNull().default('reserved'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    settledAt: timestamp('settled_at', { withTimezone: true }),
  },
  (t) => [
    index('sponsorship_reservations_tenant_state_idx').on(t.tenantId, t.chainId, t.state),
    index('sponsorship_reservations_expires_at_idx').on(t.expiresAt),
    index('sponsorship_reservations_userop_hash_idx').on(t.useropHash),
  ],
);

/** One row per observed `Sponsored` event — the R-43 breakdown a tenant reconciles against. */
export const sponsorshipSettlements = pgTable(
  'sponsorship_settlements',
  {
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
    useropHash: text('userop_hash').notNull(),
    tenantId: uuid('tenant_id').references(() => tenants.id, { onDelete: 'set null' }),
    sender: text('sender').notNull(),
    gasCostWei: numeric('gas_cost_wei', { precision: 78, scale: 0 }).notNull(),
    feeWei: numeric('fee_wei', { precision: 78, scale: 0 }).notNull(),
    overheadWei: numeric('overhead_wei', { precision: 78, scale: 0 }).notNull(),
    totalWei: numeric('total_wei', { precision: 78, scale: 0 }).notNull(),
    success: boolean('success').notNull(),
    blockNumber: bigint('block_number', { mode: 'bigint' }).notNull(),
    logIndex: bigint('log_index', { mode: 'number' }).notNull(),
    observedAt: timestamp('observed_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.chainId, t.useropHash] }),
    index('sponsorship_settlements_tenant_idx').on(t.tenantId, t.observedAt),
  ],
);

/**
 * Every evaluation, allowed or refused, including the pre-flight ones that never became
 * transactions. This is what answers "why was this sponsored?", "why was this refused?" and
 * "what was it charged?", and it is what makes a refusal-rate spike computable.
 */
export const sponsorshipDecisions = pgTable(
  'sponsorship_decisions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    tenantId: uuid('tenant_id')
      .notNull()
      .references(() => tenants.id, { onDelete: 'cascade' }),
    chainId: bigint('chain_id', { mode: 'number' }).notNull(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'set null' }),
    method: text('method', { enum: ['stub', 'data'] }).notNull(),
    sender: text('sender').notNull(),
    useropHash: text('userop_hash'),
    outcome: text('outcome', { enum: ['allowed', 'refused'] }).notNull(),
    reason: text('reason'),
    ruleResults: jsonb('rule_results').notNull().default([]),
    feeWei: numeric('fee_wei', { precision: 78, scale: 0 }),
    reservationId: uuid('reservation_id').references(() => sponsorshipReservations.id, { onDelete: 'set null' }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('sponsorship_decisions_tenant_created_idx').on(t.tenantId, t.createdAt)],
);

/** Deployment-wide chain state: the right-hand side of the accounting invariant. */
export const paymasterState = pgTable('paymaster_state', {
  chainId: bigint('chain_id', { mode: 'number' }).primaryKey(),
  paymasterAddress: text('paymaster_address').notNull(),
  treasuryWei: numeric('treasury_wei', { precision: 78, scale: 0 }).notNull().default('0'),
  depositWei: numeric('deposit_wei', { precision: 78, scale: 0 }).notNull().default('0'),
  stakeWei: numeric('stake_wei', { precision: 78, scale: 0 }).notNull().default('0'),
  lastSyncedBlock: bigint('last_synced_block', { mode: 'bigint' }),
  /** deposit − (Σ balances + treasury). Expected positive; its growth rate is the calibration signal. */
  invariantSlackWei: numeric('invariant_slack_wei', { precision: 78, scale: 0 }),
  checkedAt: timestamp('checked_at', { withTimezone: true }),
});
