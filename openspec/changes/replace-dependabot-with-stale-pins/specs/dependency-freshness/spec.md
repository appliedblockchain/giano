# Spec Delta

## Purpose

Keeps every pinned version visible against its latest qualifying release, so pins are upgraded on purpose and held back
in the open, without automated upgrade PRs.

## ADDED Requirements

### Requirement: Every pin is compared weekly with its latest qualifying release
Every week, and on demand, a check SHALL compare each pin with its latest qualifying release: the newest stable release
published at least 7 days earlier (ABIP-6). The pins SHALL include every exact npm version in the manifests of both
pnpm workspaces, every third-party action pinned to a commit SHA, Node, pnpm, Foundry, and every security tool installed
outside npm. A pin SHALL count as stale when its latest qualifying release is newer, whatever the size of the update.

#### Scenario: New release older than 7 days
- **WHEN** a pinned npm package published a newer stable version 8 days ago
- **THEN** the check reports the pin as stale, with the new version and whether the update is major, minor or patch

#### Scenario: New release younger than 7 days
- **WHEN** the only newer version of a pinned package was published 6 days ago
- **THEN** the check reports the pin as current

#### Scenario: Newer action release
- **WHEN** an action pinned to a commit SHA has a newer release older than 7 days
- **THEN** the check reports it as stale, with the commit SHA of the newer release

#### Scenario: Lookup fails
- **WHEN** the release source of a pin cannot be read
- **THEN** the check reports the pin as not checked, never as current, and fails

### Requirement: Pins on this repository's packages track its releases
A pin on one of this repository's published packages SHALL be compared with that package's version in the repository,
without reading a package registry.

#### Scenario: Example behind the release
- **WHEN** `services/custom-example` pins `@appliedblockchain/giano-connector` 6.0.0 and `packages/connector` is at 7.0.1
- **THEN** the check reports the pin as stale, with 7.0.1

### Requirement: A pin is held back only by a deferral with an owner and a review date
A pin that is deliberately not upgraded SHALL be recorded in `docs/version-deferrals.md` with its name, the held
version or major, a reason, one owner and a review date. A deferral SHALL stop the pin from counting as stale only until
its review date. A deferral that holds a major SHALL still expect the newest release within that major.

#### Scenario: Deferral expires
- **WHEN** the review date of a deferral has passed
- **THEN** the check reports the pin as stale again and says the deferral expired

#### Scenario: Held major falls behind
- **WHEN** a pin is held at major 4 and a newer 4.x release qualifies
- **THEN** the check reports the pin as stale

### Requirement: Stale pins are reported in one issue
The weekly run SHALL keep one open issue up to date with every stale pin, every pin it could not check and every
deferral in force, and SHALL close the issue when no pin is stale and every check succeeded. The run SHALL NOT be a
pull-request check, and SHALL NOT open upgrade pull requests.

#### Scenario: Stale pins found
- **WHEN** the weekly run finds a stale pin and an issue labelled `stale-pins` is open
- **THEN** it replaces that issue's body with the new report instead of opening another issue

#### Scenario: Nothing stale
- **WHEN** every pin is current or held by a deferral in force
- **THEN** the run closes the open `stale-pins` issue
