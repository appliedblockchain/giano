-- The device and browser a passkey was added from (PS-1), so the wallet can tell passkeys apart: "Added on
-- iPhone · Safari". Taken from the User-Agent of the request that created it: registration, or the deposit of a
-- passkey added from another device. Self-reported by the browser and display only. NULL for passkeys added
-- before this migration.

ALTER TABLE credentials ADD COLUMN added_device text;
ALTER TABLE credentials ADD COLUMN added_browser text;

ALTER TABLE pending_additions ADD COLUMN added_device text;
ALTER TABLE pending_additions ADD COLUMN added_browser text;
