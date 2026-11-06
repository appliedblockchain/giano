-- A claim-code challenge gets a kind of its own.
-- POST /v1/wallet/pending-additions/claim used to issue a plain 'registration' challenge bound to the slot's
-- user, so POST /v1/webauthn/registration/verify accepted it and attached a new credential, with a session,
-- to that user. With the 'pending-addition' kind, each endpoint consumes only the challenges meant for it.
--
-- Challenges still outstanding at upgrade keep their old kind and expire within the challenge TTL.

ALTER TABLE challenges DROP CONSTRAINT challenges_kind_check;
ALTER TABLE challenges ADD CONSTRAINT challenges_kind_check
  CHECK (kind IN ('registration', 'authentication', 'pending-addition'));
