-- GET /v1/platform/usage (openspec redesign-paymaster-console, B4) reads one chain's sponsorship
-- decisions and settlements over a time range of up to 90 days. The existing indexes lead with the
-- tenant, which a query across every tenant of one chain cannot use; these lead with the chain and
-- the time it filters on.
--
-- Plain CREATE INDEX, not CONCURRENTLY: the runner applies each file in a transaction. Writes to
-- these two tables wait while each index builds, which is brief at the sizes they have today.

CREATE INDEX IF NOT EXISTS sponsorship_decisions_chain_created_idx
  ON sponsorship_decisions (chain_id, created_at);

CREATE INDEX IF NOT EXISTS sponsorship_settlements_chain_observed_idx
  ON sponsorship_settlements (chain_id, observed_at);
