-- A claim-code challenge gets a kind of its own.
-- POST /v1/wallet/pending-additions/claim used to issue a plain 'registration' challenge bound to the slot's
-- user, so POST /v1/webauthn/registration/verify accepted it and attached a new credential, with a session,
-- to that user. With the 'pending-addition' kind, each endpoint consumes only the challenges meant for it.

ALTER TABLE challenges DROP CONSTRAINT challenges_kind_check;
ALTER TABLE challenges ADD CONSTRAINT challenges_kind_check
  CHECK (kind IN ('registration', 'authentication', 'pending-addition'));

-- A claim challenge issued before this migration still has the 'registration' kind, so registration/verify
-- would accept it until it expires. It cannot be told apart from a registration challenge for an existing
-- user, so consume every outstanding 'registration' challenge that is bound to a user. A claim challenge is
-- always bound to one (pending_additions.user_id is NOT NULL). Registration of a new user (user_id NULL) is
-- not affected; an existing user who was adding a passkey at upgrade time starts that ceremony again.
UPDATE challenges SET consumed_at = now()
 WHERE kind = 'registration' AND user_id IS NOT NULL AND consumed_at IS NULL;
