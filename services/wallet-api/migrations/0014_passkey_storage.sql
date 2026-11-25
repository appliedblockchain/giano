-- Where a passkey is stored, so the wallet can show it (PS-1): the provider that made it and whether it is
-- synced. Read from the authenticator's data at registration, and at fill for a passkey added from another
-- device. A sign-in refreshes the two flags, because a passkey can start or stop syncing.
--   aaguid       the authenticator's AAGUID: names the passkey provider (Google Password Manager, Apple
--                Passwords, 1Password, ...). All zeros when the provider does not report one.
--   device_type  'singleDevice' (cannot leave the authenticator) or 'multiDevice' (can be synced).
--   backed_up    whether the passkey is currently backed up, i.e. synced.
-- Credentials registered before this migration have NULL in all three: their provider is unknown, and the
-- flags fill in at their next sign-in.

ALTER TABLE credentials ADD COLUMN aaguid text;
ALTER TABLE credentials ADD COLUMN device_type text;
ALTER TABLE credentials ADD COLUMN backed_up boolean;

ALTER TABLE pending_additions ADD COLUMN aaguid text;
ALTER TABLE pending_additions ADD COLUMN device_type text;
ALTER TABLE pending_additions ADD COLUMN backed_up boolean;
