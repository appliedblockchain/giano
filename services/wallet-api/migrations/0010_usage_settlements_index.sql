-- GET /v1/platform/usage (B4) reads one chain's settlements over a time range; this index leads
-- with the chain and the time, as 0010_usage_decisions_index does for decisions. Its own file and
-- a lock timeout, for the same reasons.

SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS sponsorship_settlements_chain_observed_idx
  ON sponsorship_settlements (chain_id, observed_at);
