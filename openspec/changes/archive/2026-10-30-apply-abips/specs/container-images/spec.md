## MODIFIED Requirements

### Requirement: Exceptions are recorded
Any image or stage that cannot use a Docker Hardened Image SHALL be listed in `docs/abip-compliance.md`. Each entry
SHALL give:
- the image;
- the reason no hardened equivalent exists;
- the mitigation in place;
- a link to a tracking issue, which SHALL exist in the repository and SHALL be open.

The Dockerfile policy check SHALL accept a non-DHI base only for an image listed there. ABIP-2 allows exceptions only
for third-party images, so whole-file exemptions SHALL NOT be used. `giano-devnet`, which is built on the Foundry image,
is the only recorded exception. `giano-contracts-deployer` is in scope and meets every requirement of this capability,
like any other published image.

#### Scenario: Recorded exception passes
- **WHEN** the policy check runs over `services/devnet/Dockerfile`, which is listed as an exception
- **THEN** it accepts the digest-pinned Foundry base and still requires the digest pin

#### Scenario: Unrecorded exception fails
- **WHEN** a Dockerfile not listed in `docs/abip-compliance.md` uses a non-DHI base
- **THEN** the policy check fails CI

#### Scenario: Placeholder tracking issue rejected
- **WHEN** an exception entry's tracking issue reads "to be opened" or links an issue that does not exist
- **THEN** the change that records the exception is not complete

#### Scenario: Deployer is hardened
- **WHEN** `docker run --entrypoint sh ghcr.io/appliedblockchain/giano-contracts-deployer@<digest>` is attempted
- **THEN** it fails because no shell exists, and the image's main process runs as the DHI non-root user
