-- Tenant lifecycle and the operator tier (openspec change operator-tenant-lifecycle,
-- specs/OPERATOR-ADMIN-SPECS.md §5.2).
--
-- Tenants stop being seed-only. Giano's operators create, edit, suspend and delete them at
-- runtime, so a tenant gains a lifecycle (active → suspended → deleted), an owner (the seed or
-- the operators, never both), and a version that every write increments. Only an active tenant
-- resolves. Delete is a tombstone: the row stays, so its slug, id, wallet origin and RP ID can
-- never be handed to someone else.
--
-- Who is an operator is configuration (OPERATOR_ADDRESSES), never a row. The two operator tables
-- below hold only sign-in state, and the guard ignores any session whose address the current
-- configuration does not list.

ALTER TABLE tenants
  ADD COLUMN status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended', 'deleted')),
  -- every existing row came from TENANTS_SEED, or is the 0002 'default' backfill (rp_id
  -- 'migrated.invalid') that only a seed entry can claim, so 'seed' is the correct backfill for both
  ADD COLUMN managed_by text NOT NULL DEFAULT 'seed'
    CHECK (managed_by IN ('seed', 'operator')),
  -- incremented by every write, seed writes included; the ETag for PATCH
  ADD COLUMN version integer NOT NULL DEFAULT 1,
  ADD COLUMN status_changed_at timestamptz;

CREATE INDEX tenants_status_idx ON tenants (status);

-- 'seed' | 'operator:<id>:<address>'
ALTER TABLE tenant_admin_keys
  ADD COLUMN created_by text NOT NULL DEFAULT 'seed';

-- EIP-4361 sign-in challenges. Rows, not memory, because a nonce issued by one replica must be
-- consumable by another. The exact message text is stored so verify accepts only what was issued.
CREATE TABLE operator_challenges (
  nonce text PRIMARY KEY,
  -- lowercase
  address text NOT NULL,
  message text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX operator_challenges_expires_idx ON operator_challenges (expires_at);

-- Kept after expiry: the record of who signed in when, and tenant_history references them.
CREATE TABLE operator_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- sha256 hex of the gos_ token; the token itself is never stored
  token_hash text NOT NULL UNIQUE,
  -- the OPERATOR_ADDRESSES id at sign-in
  operator_id text NOT NULL,
  -- lowercase
  address text NOT NULL,
  -- from the signed message, for the record
  chain_id bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  ip text,
  user_agent text
);

CREATE INDEX operator_sessions_expires_idx ON operator_sessions (expires_at);

-- Append-only. No cascade: tenants are never hard-deleted. before/after never carry key
-- material; admin-key actions record { keyId, label, hashPrefix } in detail.
CREATE TABLE tenant_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  action text NOT NULL CHECK (action IN (
    'create', 'update', 'suspend', 'resume', 'delete',
    'admin-key-issue', 'admin-key-revoke', 'seed-apply', 'seed-takeover', 'adopt'
  )),
  -- 'seed' | 'operator:<id>:<address>'
  actor text NOT NULL,
  -- null for seed writes
  operator_session_id uuid REFERENCES operator_sessions(id),
  -- the tenant row before the write; null on create
  before jsonb,
  after jsonb,
  detail jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX tenant_history_tenant_idx ON tenant_history (tenant_id, created_at);
