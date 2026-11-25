# Tasks

- [x] 1. wallet-api: migration `0015_passkey_added_from.sql`; User-Agent parsing (`services/user-agent.ts`); recorded at registration and fill, carried at complete; `addedFrom` on credentials and on the pending-addition poll; OpenAPI. Tests: User-Agent strings; registration, deposit from an iPhone, the poll, the bound row.
- [x] 2. wallet-core `PasskeyAddedFrom`; wallet-kit `OwnerRow.addedFrom` and the consent step's `addedFrom` (from the poll, and from the slot for a same-device passkey). Tests.
- [x] 3. wallet-kit `signIn` is discoverable; `signInWithExistingPasskey` a deprecated alias. Test.
- [x] 4. Stock wallet: row subtitle with the device and browser, no raw transports; consent "Created on" and default name; one sign-in button; claim copy. BYO parity.
- [x] 5. e2e: device B as an iPhone with Safari, seen and named on device A; every test that signed in with the second button now uses the single one.
