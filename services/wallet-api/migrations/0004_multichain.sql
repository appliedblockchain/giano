-- Multi-chain: the relay audit trail records the chain for every operation (MC-59), so
-- "which chain did this go to" is answerable directly rather than by inference.
--
-- NOT NULL from the outset: nothing is in production (clean-state assumption, Q4), so there
-- is nothing to backfill. The transient DEFAULT only carries any pre-existing local rows —
-- it is dropped immediately so new inserts must state the chain.
ALTER TABLE userop_log ADD COLUMN chain_id bigint NOT NULL DEFAULT 0;
ALTER TABLE userop_log ALTER COLUMN chain_id DROP DEFAULT;

CREATE INDEX userop_log_chain_id_created_at_idx ON userop_log (chain_id, created_at);
