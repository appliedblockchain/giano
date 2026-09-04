-- Wallet management (specs/WALLET-MANAGEMENT-REQUIREMENTS.md).
--
-- Three structural changes:
--   1. Sessions record the WALLET they are scoped to (WM-33/D3), not just the credential —
--      any credential that is an owner of a wallet may open a session for it, and the
--      relay's sender-binding rule keeps working with no exceptions (WM-34).
--   2. Credentials gain a user-set name (WM-07/WM-08 — the previously-discarded
--      `credentialName` is now persisted) and a `removed_at` marker: a credential whose
--      owner key was removed on-chain stays in the registry for honest display (WM-04)
--      but can no longer authenticate (WM-31).
--   3. Pending additions (D8): the slot a second device deposits a new public key into,
--      opened by the authorising device, single-use, short-lived, inert until an existing
--      credential signs for it. Recorded on creation, fill, consumption, decline and
--      expiry (WM-51), with declined fingerprints countable (WM-52).

ALTER TABLE credentials ADD COLUMN name text;
ALTER TABLE credentials ADD COLUMN removed_at timestamptz;

-- NOT NULL via a transient backfill (clean-state assumption, as in 0004): existing rows
-- inherit the credential's wallet, which is exactly what the join used to compute.
ALTER TABLE sessions ADD COLUMN wallet_address text;
UPDATE sessions SET wallet_address = c.wallet_address FROM credentials c WHERE sessions.credential_id = c.id;
ALTER TABLE sessions ALTER COLUMN wallet_address SET NOT NULL;
CREATE INDEX sessions_credential_id_idx ON sessions (credential_id);

CREATE TABLE pending_additions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The wallet the addition targets — from the AUTHORISING device's session (WM-19),
  -- never asserted by the device that fills the slot.
  wallet_address text NOT NULL,
  -- Routes the ceremony; authorises nothing. Globally unique so a claim resolves the slot.
  claim_code text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'open', -- open | filled | consumed | declined | expired
  -- The deposited credential — null until the second device fills the slot. Inert: no
  -- owner is added and no session is granted by anything in this table.
  credential_id text,
  cose_public_key bytea,
  public_key_x text,
  public_key_y text,
  transports text[],
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  filled_at timestamptz,
  consumed_at timestamptz
);
CREATE INDEX pending_additions_user_id_idx ON pending_additions (user_id);
CREATE INDEX pending_additions_expires_at_idx ON pending_additions (expires_at);

-- Durable audit of every attempted owner-set change (WM-50): who authorised it, what it
-- did, on which chains, and how each refusal was grounded — answerable without re-running
-- anything. The relay's userop_log rows record the transactions themselves; this table
-- records the MANAGEMENT lifecycle around them.
CREATE TABLE wallet_management_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
  wallet_address text NOT NULL,
  action text NOT NULL,  -- pending-opened | pending-filled | pending-consumed | pending-declined |
                         -- pending-expired | owner-added | owner-removed | binding-refused | owner-event
  outcome text NOT NULL, -- ok | refused
  detail jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX wallet_management_log_wallet_idx ON wallet_management_log (wallet_address, created_at);
CREATE INDEX wallet_management_log_tenant_idx ON wallet_management_log (tenant_id, created_at);
