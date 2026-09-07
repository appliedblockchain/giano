-- Giano wallet-api initial schema.
-- Plain SQL migrations, applied in filename order by src/migrate.ts (bundled into the image).

CREATE TABLE IF NOT EXISTS migrations (
  filename text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- The client project's own user identifier: the binding point between the
  -- client application's auth and Giano credentials (R6a).
  external_id text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- base64url credential id as sent by the authenticator
  credential_id text NOT NULL UNIQUE,
  -- COSE public key bytes as returned by @simplewebauthn verification
  cose_public_key bytea NOT NULL,
  -- P-256 coordinates, 0x-prefixed 32-byte hex each (the smart wallet owner key)
  public_key_x text NOT NULL,
  public_key_y text NOT NULL,
  counter bigint NOT NULL DEFAULT 0,
  transports text[],
  -- counterfactual (or deployed) smart wallet address bound to this credential
  wallet_address text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX credentials_user_id_idx ON credentials(user_id);
CREATE INDEX credentials_wallet_address_idx ON credentials(wallet_address);

CREATE TABLE challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- base64url-encoded challenge bytes
  challenge text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('registration', 'authentication')),
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  -- one-time use: consumption is UPDATE … WHERE consumed_at IS NULL AND expires_at > now() RETURNING *
  consumed_at timestamptz
);
CREATE INDEX challenges_expires_at_idx ON challenges(expires_at);

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id uuid NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  -- sha256 hex of the opaque bearer token; the token itself is never stored
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);

CREATE TABLE userop_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- server-side computed hash; unique => idempotency + audit
  userop_hash text NOT NULL UNIQUE,
  sender text NOT NULL,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
  status text NOT NULL CHECK (status IN ('accepted', 'rejected', 'submitted', 'failed')),
  -- per-rule audit trail of the policy pipeline, one entry per rule evaluated
  policy_results jsonb NOT NULL DEFAULT '[]',
  reject_reason text,
  bundler_response jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX userop_log_sender_idx ON userop_log(sender);

CREATE TABLE ror_origins (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  origin text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
