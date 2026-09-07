-- Multi-tenancy: one wallet-api serves many tenants, where tenant ≡ wallet origin ≡ RP ID
-- (specs/DEVELOPER-GUIDE.md §1). Runs in a single transaction (src/migrate.ts).

-- ── Tenants ────────────────────────────────────────────────────────────────────

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- stable human-readable identifier: seed idempotency key and metric label
  slug text NOT NULL UNIQUE,
  -- the browser origin serving this tenant's wallet UI, e.g. 'https://wallet.keo.com'
  wallet_origin text NOT NULL UNIQUE,
  -- WebAuthn relying-party id = host of wallet_origin. IMMUTABLE once the tenant's
  -- first passkey exists (passkeys bind to it irreversibly) — enforced by the seeder.
  rp_id text NOT NULL UNIQUE,
  rp_name text NOT NULL,
  -- ceremony origins; every entry's host must equal rp_id or be a subdomain of it
  -- (validated on the write path, src/services/tenants.ts)
  expected_origins text[] NOT NULL,
  -- dApp origins allowed to drive this tenant's wallet (informational for the API;
  -- enforced browser-side by the wallet UI's transport allowlist)
  allowed_dapp_origins text[] NOT NULL DEFAULT '{}',
  -- origins granted CORS against the API (typically the tenant's dApp origins)
  cors_origins text[] NOT NULL DEFAULT '{}',
  open_registration boolean NOT NULL DEFAULT false,
  -- partial userop PolicyConfig overrides (bigints as decimal strings); merged over
  -- the deployment-wide USEROP_* defaults per request
  policy jsonb NOT NULL DEFAULT '{}',
  branding jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_admin_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- sha256 hex of the plaintext key; globally unique so key → tenant is unambiguous
  key_hash text NOT NULL UNIQUE,
  label text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_admin_keys_tenant_id_idx ON tenant_admin_keys(tenant_id);

-- ── Tenant columns (nullable first, backfill, then NOT NULL) ───────────────────

ALTER TABLE users ADD COLUMN tenant_id uuid REFERENCES tenants(id);
ALTER TABLE credentials ADD COLUMN tenant_id uuid REFERENCES tenants(id);
-- the RP ID the credential was registered under (defence in depth for C2)
ALTER TABLE credentials ADD COLUMN rp_id text;
ALTER TABLE challenges ADD COLUMN tenant_id uuid REFERENCES tenants(id);
ALTER TABLE ror_origins ADD COLUMN tenant_id uuid REFERENCES tenants(id);
ALTER TABLE userop_log ADD COLUMN tenant_id uuid REFERENCES tenants(id);
-- sessions carry no tenant column: a session's tenant derives from its user's
-- tenant_id (users are created tenant-scoped and never move).

-- Backfill: only when a pre-tenancy deployment has data. The '.invalid' sentinel rp_id
-- marks the row as claimable — a TENANTS_SEED entry with slug 'default' may rewrite it
-- (the one exception to rp_id immutability), letting the deployment adopt its real origin.
DO $$
DECLARE t uuid;
BEGIN
  IF EXISTS (SELECT 1 FROM users) OR EXISTS (SELECT 1 FROM challenges)
     OR EXISTS (SELECT 1 FROM ror_origins) OR EXISTS (SELECT 1 FROM userop_log) THEN
    INSERT INTO tenants (slug, wallet_origin, rp_id, rp_name, expected_origins, open_registration)
    VALUES ('default', 'https://migrated.invalid', 'migrated.invalid', 'Default (migrated)',
            ARRAY['https://migrated.invalid'], false)
    RETURNING id INTO t;
    UPDATE users SET tenant_id = t WHERE tenant_id IS NULL;
    UPDATE credentials SET tenant_id = t, rp_id = 'migrated.invalid' WHERE tenant_id IS NULL;
    UPDATE challenges SET tenant_id = t WHERE tenant_id IS NULL;
    UPDATE ror_origins SET tenant_id = t WHERE tenant_id IS NULL;
    UPDATE userop_log SET tenant_id = t WHERE tenant_id IS NULL;
  END IF;
END $$;

ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE credentials ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE credentials ALTER COLUMN rp_id SET NOT NULL;
ALTER TABLE challenges ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ror_origins ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE userop_log ALTER COLUMN tenant_id SET NOT NULL;

-- ── Unique swaps: global → per-tenant ─────────────────────────────────────────
-- Constraint names are the inline-UNIQUE Postgres defaults from 0001 (<table>_<col>_key).
-- Deliberately UNTOUCHED (must stay global): sessions_token_hash_key (bearer-token
-- anti-collision), userop_log_userop_hash_key (chain-level fact backing idempotency),
-- challenges_challenge_key (32 random bytes; tenant binding is enforced on consume).

ALTER TABLE users DROP CONSTRAINT users_external_id_key;
-- C1: two tenants may (and will) pick the same external id — they must be distinct users
ALTER TABLE users ADD CONSTRAINT users_tenant_id_external_id_key UNIQUE (tenant_id, external_id);

ALTER TABLE credentials DROP CONSTRAINT credentials_credential_id_key;
ALTER TABLE credentials ADD CONSTRAINT credentials_tenant_id_credential_id_key UNIQUE (tenant_id, credential_id);
-- authentication/verify resolves by credential_id alone (then tenant-checks, so the
-- cross-tenant rejection stays alertable) — keep that lookup indexed
CREATE INDEX credentials_credential_id_idx ON credentials(credential_id);

ALTER TABLE ror_origins DROP CONSTRAINT ror_origins_origin_key;
ALTER TABLE ror_origins ADD CONSTRAINT ror_origins_tenant_id_origin_key UNIQUE (tenant_id, origin);

-- ── Indexes ────────────────────────────────────────────────────────────────────

CREATE INDEX userop_log_tenant_id_created_at_idx ON userop_log(tenant_id, created_at);
