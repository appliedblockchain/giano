-- A challenge records the external user id it was requested for.
-- POST /v1/webauthn/options issued a registration challenge with user_id NULL when the external user did not
-- exist yet. POST /v1/webauthn/registration/verify then accepted any externalUserId in the body for that
-- challenge, and attached the new credential to whichever user had that id, including an existing one.
-- registration/verify now requires external_id to equal the body's externalUserId.

ALTER TABLE challenges ADD COLUMN external_id text;

-- A registration challenge issued before this migration has no external_id, so registration/verify refuses
-- it. Consume them now, so the refusal is "unknown, expired or already used" rather than a user mismatch.
-- A user who was registering at upgrade time starts that ceremony again.
UPDATE challenges SET consumed_at = now()
 WHERE kind = 'registration' AND consumed_at IS NULL;
