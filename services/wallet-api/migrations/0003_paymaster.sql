-- Gas sponsorship: per-tenant rules, the reservation ledger and the settlement record.
-- Runs in a single transaction (src/migrate.ts).
--
-- Three kinds of state live here, and the distinction matters:
--
--   * RULES  (tenant_sponsorship)     — the tenant's own, written only through its admin key.
--                                       TENANTS_SEED never touches these, so a restart cannot
--                                       revert a tenant's edit, and a tenant with no row
--                                       sponsors nothing.
--   * CHAIN  (paymaster_tenants,      — a cache of on-chain truth, rebuilt from paymaster events
--             paymaster_state,          and reconciled against the EntryPoint deposit. Never the
--             sponsorship_settlements)  authority: if it disagrees with the chain, it is wrong.
--   * OURS   (sponsorship_reservations,— the only state the service owns outright. Reservations
--             sponsorship_decisions)    are what stop concurrently authorised operations from
--                                       collectively overdrawing a balance.

-- ── Rules ──────────────────────────────────────────────────────────────────────

CREATE TABLE tenant_sponsorship (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  -- validated by the zod schema in src/services/sponsorship-config.ts on every write, and
  -- re-validated on read: an unparseable value means NO sponsorship, never unrestricted
  config jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- sha256 of the admin key that wrote it: who changed the rules, without storing the key
  updated_by_key_hash text,
  PRIMARY KEY (tenant_id, chain_id)
);

CREATE TABLE tenant_sponsorship_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  config jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by_key_hash text
);

CREATE INDEX tenant_sponsorship_history_tenant_idx
  ON tenant_sponsorship_history (tenant_id, created_at DESC);

-- ── Chain state cache ──────────────────────────────────────────────────────────

-- numeric(78,0) throughout: wei does not fit a bigint and must not become a float.
CREATE TABLE paymaster_tenants (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  paymaster_address text NOT NULL,
  balance_wei numeric(78,0) NOT NULL DEFAULT 0,
  -- money the pooled deposit already absorbed on this tenant's behalf. Non-zero blocks
  -- further authorisation for this tenant until it funds (§7.5).
  deficit_wei numeric(78,0) NOT NULL DEFAULT 0,
  withdraw_address text,
  last_synced_block bigint,
  last_synced_at timestamptz,
  PRIMARY KEY (tenant_id, chain_id),
  CONSTRAINT paymaster_tenants_balance_non_negative CHECK (balance_wei >= 0),
  CONSTRAINT paymaster_tenants_deficit_non_negative CHECK (deficit_wei >= 0)
);

CREATE TABLE paymaster_state (
  chain_id bigint PRIMARY KEY,
  paymaster_address text NOT NULL,
  treasury_wei numeric(78,0) NOT NULL DEFAULT 0,
  deposit_wei numeric(78,0) NOT NULL DEFAULT 0,
  stake_wei numeric(78,0) NOT NULL DEFAULT 0,
  last_synced_block bigint,
  -- deposit − (Σ balances + treasury). Expected positive and safe; a negative value is an
  -- insolvency, and unexpectedly fast growth means tenants are being overcharged.
  invariant_slack_wei numeric(78,0),
  checked_at timestamptz
);

CREATE TABLE sponsorship_settlements (
  chain_id bigint NOT NULL,
  userop_hash text NOT NULL,
  tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
  sender text NOT NULL,
  -- kept separate rather than summed, so a tenant can see what was gas, what was Giano's
  -- margin and what was overhead
  gas_cost_wei numeric(78,0) NOT NULL,
  fee_wei numeric(78,0) NOT NULL,
  overhead_wei numeric(78,0) NOT NULL,
  total_wei numeric(78,0) NOT NULL,
  success boolean NOT NULL,
  block_number bigint NOT NULL,
  log_index bigint NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, userop_hash)
);

CREATE INDEX sponsorship_settlements_tenant_idx
  ON sponsorship_settlements (tenant_id, observed_at DESC);

-- ── Reservations ───────────────────────────────────────────────────────────────

CREATE TABLE sponsorship_reservations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  sender text NOT NULL,
  nonce numeric(78,0) NOT NULL,
  userop_hash text,
  max_cost_wei numeric(78,0) NOT NULL,
  fee_wei numeric(78,0) NOT NULL,
  overhead_wei numeric(78,0) NOT NULL,
  total_wei numeric(78,0) NOT NULL,
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved', 'settled', 'expired', 'released')),
  -- set slightly beyond the authorisation's validUntil, so an operation can never be valid
  -- on-chain while its reservation has already been swept back
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  settled_at timestamptz
);

-- Two live reservations for one (chain, sender, nonce) would double-count against the balance.
-- A partial unique index makes that a database error rather than a race.
CREATE UNIQUE INDEX sponsorship_reservations_live_key
  ON sponsorship_reservations (chain_id, sender, nonce)
  WHERE state = 'reserved';

CREATE INDEX sponsorship_reservations_tenant_state_idx
  ON sponsorship_reservations (tenant_id, chain_id, state);
CREATE INDEX sponsorship_reservations_expires_at_idx
  ON sponsorship_reservations (expires_at) WHERE state = 'reserved';
CREATE INDEX sponsorship_reservations_userop_hash_idx
  ON sponsorship_reservations (userop_hash);

-- ── Decisions ──────────────────────────────────────────────────────────────────

CREATE TABLE sponsorship_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
  -- 'stub' includes the wallet's pre-approval check, which never becomes a transaction but is
  -- exactly the decision a user was shown
  method text NOT NULL CHECK (method IN ('stub', 'data')),
  sender text NOT NULL,
  userop_hash text,
  outcome text NOT NULL CHECK (outcome IN ('allowed', 'refused')),
  reason text,
  rule_results jsonb NOT NULL DEFAULT '[]'::jsonb,
  fee_wei numeric(78,0),
  reservation_id uuid REFERENCES sponsorship_reservations(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sponsorship_decisions_tenant_created_idx
  ON sponsorship_decisions (tenant_id, created_at DESC);
CREATE INDEX sponsorship_decisions_outcome_idx
  ON sponsorship_decisions (tenant_id, outcome, created_at DESC);

-- ── Relay linkage ──────────────────────────────────────────────────────────────

-- "why was this sponsored, and what was it charged" becomes one join from the relay audit row.
-- Deliberately not a foreign key: the relay must never fail to record a userop because the
-- decision row was pruned.
ALTER TABLE userop_log ADD COLUMN sponsorship_decision_id uuid;
