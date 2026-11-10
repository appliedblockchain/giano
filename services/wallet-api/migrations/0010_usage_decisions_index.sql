-- GET /v1/platform/usage (openspec redesign-paymaster-console, B4) reads one chain's sponsorship
-- decisions over a time range of up to 90 days. The existing indexes lead with the tenant, which a
-- query across every tenant of one chain cannot use; this one leads with the chain and the time.
--
-- Plain CREATE INDEX, not CONCURRENTLY: the runner applies each file in a transaction. One index
-- per file, so this table's lock is held only while its own index builds, and a lock timeout, so a
-- long transaction on the table fails the migration rather than queue every new insert behind it.

SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS sponsorship_decisions_chain_created_idx
  ON sponsorship_decisions (chain_id, created_at);
