-- Each chain's relay policy in the database (openspec change chain-relay-policy-console, G6).
--
-- One row per chain: the caps and allowlists the relay applies to every tenant on that chain, unless
-- a GIANO_CHAINS descriptor or a USEROP_* env var overrides a field, or the tenant's own policy does.
-- The policy has the shape of a descriptor's walletApi.policy and is validated on every write and
-- every read. `version` guards a write with If-Match. wallet-api seeds a row for every served chain
-- that has none when it starts; nothing here inserts one, because the served chains are runtime
-- configuration.
--
-- The history is append-only: 'seed' (written by wallet-api at boot) or 'update' (a platform admin).

CREATE TABLE chain_relay_policy (
  chain_id bigint PRIMARY KEY,
  policy jsonb NOT NULL,
  version integer NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- 'platform-admin:<id>:<address>' | 'system:seed'
  updated_by text NOT NULL
);

CREATE TABLE chain_relay_policy_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  chain_id bigint NOT NULL,
  action text NOT NULL CHECK (action IN ('seed', 'update')),
  actor text NOT NULL,
  platform_admin_session_id uuid REFERENCES platform_admin_sessions (id),
  before jsonb,
  after jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX chain_relay_policy_history_chain_idx ON chain_relay_policy_history (chain_id, created_at);
