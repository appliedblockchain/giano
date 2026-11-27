-- A tenant's sponsorship rules become records (openspec sponsorship-rules-api).
--
-- Until now a tenant named the contracts it sponsors in one `allowlist` array inside
-- tenant_sponsorship.config, and every change rewrote the whole array. A tenant that deploys a
-- contract for every payment needs to add one rule at a time, and two writes at the same time
-- could lose one of them. Each rule is now a row: one per tenant, chain and contract.
--
-- config.allowlist stays in place. It mirrors the rules that have no client_reference, so a
-- rollback to the previous release still sponsors what it sponsored before (design D8).

CREATE TABLE tenant_sponsorship_rules (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	chain_id bigint NOT NULL,
	-- lower case, as the rules engine compares it
	contract text NOT NULL,
	-- "all", or a JSON array of 4-byte selectors
	functions jsonb NOT NULL,
	-- the tenant's own reference, so a retried create returns the same rule
	client_reference text,
	-- after this time the rule allows nothing
	expires_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	created_by_key_hash text,
	updated_by_key_hash text,
	CONSTRAINT tenant_sponsorship_rules_contract_key UNIQUE (tenant_id, chain_id, contract)
);

CREATE UNIQUE INDEX tenant_sponsorship_rules_reference_key
	ON tenant_sponsorship_rules (tenant_id, chain_id, client_reference)
	WHERE client_reference IS NOT NULL;

-- Counting active rules for the cap, and removing expired ones.
CREATE INDEX tenant_sponsorship_rules_expires_idx
	ON tenant_sponsorship_rules (tenant_id, chain_id, expires_at);

-- Who created, changed or removed which rule. rule_id is not a foreign key: a removed rule keeps
-- its events.
CREATE TABLE tenant_sponsorship_rule_events (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	chain_id bigint NOT NULL,
	rule_id uuid NOT NULL,
	action text NOT NULL CHECK (action IN ('created', 'updated', 'deleted', 'expired-removed')),
	rule jsonb NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	-- null when wallet-api made the change itself: this migration, or removing an expired rule
	created_by_key_hash text
);

CREATE INDEX tenant_sponsorship_rule_events_tenant_idx
	ON tenant_sponsorship_rule_events (tenant_id, chain_id, created_at);

-- Settings writes are versioned, so two edits from the same version cannot both succeed.
ALTER TABLE tenant_sponsorship ADD COLUMN version integer NOT NULL DEFAULT 0;
UPDATE tenant_sponsorship SET version = 1;

-- The rules that allowed each decision.
ALTER TABLE sponsorship_decisions ADD COLUMN rule_ids uuid[] NOT NULL DEFAULT '{}';

-- Every stored allowlist entry becomes a rule with no reference and no expiry. A stored entry was
-- validated on write, so its contract is an address and its functions are "all" or selectors.
-- DISTINCT ON keeps one rule per contract if a row written by hand repeats one.
WITH entries AS (
	SELECT DISTINCT ON (s.tenant_id, s.chain_id, lower(entry->>'contract'))
		s.tenant_id,
		s.chain_id,
		lower(entry->>'contract') AS contract,
		entry->'functions' AS functions
	FROM tenant_sponsorship s
	CROSS JOIN LATERAL jsonb_array_elements(
		CASE WHEN jsonb_typeof(s.config->'allowlist') = 'array' THEN s.config->'allowlist' ELSE '[]'::jsonb END
	) AS entry
	WHERE jsonb_typeof(entry) = 'object'
		AND entry->>'contract' ~* '^0x[0-9a-f]{40}$'
		AND (entry->'functions' = '"all"'::jsonb OR jsonb_typeof(entry->'functions') = 'array')
),
inserted AS (
	INSERT INTO tenant_sponsorship_rules (tenant_id, chain_id, contract, functions)
	SELECT tenant_id, chain_id, contract, functions FROM entries
	RETURNING id, tenant_id, chain_id, contract, functions, created_at
)
INSERT INTO tenant_sponsorship_rule_events (tenant_id, chain_id, rule_id, action, rule)
SELECT
	tenant_id,
	chain_id,
	id,
	'created',
	jsonb_build_object(
		'id', id,
		'contract', contract,
		'functions', functions,
		'clientReference', NULL,
		'expiresAt', NULL,
		'createdAt', created_at
	)
FROM inserted;
