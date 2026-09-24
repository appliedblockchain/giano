-- Transaction display mappings (openspec change transaction-display-mappings).
--
-- A tenant explains its contracts to wallet users with ERC-7730 descriptors, one per
-- (chain, contract): the wallet's review screen renders "Send 10.5 USDC to 0x1234…abcd" from
-- them instead of hex calldata. Like the sponsorship rules, these are the tenant's own data,
-- written only through its admin key — TENANTS_SEED never touches them — and every write is
-- validated against the descriptor rules in @appliedblockchain/giano-tx-describe and
-- re-validated when served, so a row the current code no longer trusts is skipped, never
-- shown to a user as an explanation.

CREATE TABLE tenant_tx_mappings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  -- lowercase 0x-prefixed address; the descriptor's own deployments must include (chain_id, contract)
  contract text NOT NULL,
  descriptor jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- sha256 of the admin key that wrote it: who changed the mapping, without storing the key
  updated_by_key_hash text,
  UNIQUE (tenant_id, chain_id, contract)
);

CREATE TABLE tenant_tx_mappings_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  chain_id bigint NOT NULL,
  contract text NOT NULL,
  action text NOT NULL CHECK (action IN ('put', 'delete')),
  -- the descriptor written; NULL for a delete
  descriptor jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by_key_hash text
);

CREATE INDEX tenant_tx_mappings_history_tenant_idx
  ON tenant_tx_mappings_history (tenant_id, chain_id, created_at DESC);
