# demo-deployment Specification

## Purpose

The container contract of the `giano-example` image: one build serves every environment and both tenant shapes, with
configuration injected at start and nothing secret in the public bundle.

## Requirements

### Requirement: Configuration is injected at container start
The image SHALL contain no environment-specific value. At start, the container SHALL render `/config.js` from `GIANO_*`
environment variables and then serve the static bundle. The rendered file SHALL be served with `Cache-Control: no-store`.

#### Scenario: Same image, two tenants
- **WHEN** the image starts twice with different `GIANO_WALLET_URL` and `GIANO_APP_LABEL`
- **THEN** each instance is pinned to its own wallet origin and labelled accordingly, with no rebuild

#### Scenario: Placeholder substitution only
- **WHEN** a configuration value contains `$`, quotes or backslashes
- **THEN** the rendered file is valid JavaScript and the value round-trips unchanged

### Requirement: Chain list configuration
The container SHALL accept `GIANO_CHAINS` as a JSON array of `{ chainId, name, rpcUrl, explorerUrl?, defaultToken? }`.
For one release it SHALL also accept the scalar pair `GIANO_CHAIN_ID` / `GIANO_CHAIN_B_ID` (with names, RPC URLs and
`GIANO_TEST_ERC20`), converting it to the list form and logging a deprecation line. Supplying both SHALL fail start-up.

#### Scenario: JSON list
- **WHEN** `GIANO_CHAINS` names three chains
- **THEN** the selector offers all three in that order

#### Scenario: Legacy scalars
- **WHEN** only `GIANO_CHAIN_ID` and friends are set
- **THEN** the demo behaves as with an equivalent `GIANO_CHAINS` and the start-up log says the scalars are deprecated

#### Scenario: Invalid configuration
- **WHEN** `GIANO_CHAINS` is not a JSON array, or both it and the scalar pair are set
- **THEN** the container exits non-zero with the problem named, before serving anything

#### Scenario: Incomplete chain entry
- **WHEN** `GIANO_CHAINS` is a JSON array but a chain lacks `rpcUrl` or has an invalid field
- **THEN** the container serves the page and the browser renders the configuration-error screen naming the field
  (the container has no JSON parser; field validation is the browser's)

### Requirement: Optional disallowed-origin probe target
The container SHALL accept `GIANO_OTHER_WALLET_URL`, an optional wallet origin that does not allow-list this dApp, and
render it as `otherWalletUrl` so the failure lab can provoke an `origin-not-allowed` refusal. When unset, the control
SHALL be hidden.

#### Scenario: Second tenant configured
- **WHEN** `GIANO_OTHER_WALLET_URL` names the other tenant's wallet origin
- **THEN** the disallowed-origin control is shown and connecting through it is refused with `origin-not-allowed`

### Requirement: Browser-side validation and error screen
The bundle SHALL validate the runtime configuration on load. An invalid or missing configuration SHALL render a
configuration-error screen naming the invalid fields; no provider SHALL be constructed.

#### Scenario: Missing wallet URL
- **WHEN** `walletUrl` is absent from the runtime configuration
- **THEN** the page shows the configuration error naming `walletUrl` and offers nothing else

### Requirement: No secrets in the bundle or in `/config.js`
The build SHALL not embed any `VITE_*` value other than local-development fallbacks. A keyed RPC URL SHALL only be used
via the container's same-origin proxy path, configured by an upstream variable that is never rendered into `/config.js`
or into response headers.

#### Scenario: Keyed RPC via proxy
- **WHEN** a chain's `rpcUrl` is `/rpc/<chainId>` and `GIANO_RPC_UPSTREAM_<chainId>` carries the keyed URL
- **THEN** browser requests go to the same origin, the key never appears in `/config.js` or the CSP header, and the
  demo works

#### Scenario: Bundle scan
- **WHEN** the built assets are scanned for `VITE_` values and for `navigator.credentials`
- **THEN** neither is found

### Requirement: Security headers
Responses SHALL carry `X-Frame-Options: DENY`, a Content-Security-Policy whose `connect-src` is exactly `'self'`, the chain
RPC origins and the wallet origins (the same-origin `/rpc/<chainId>` proxies are covered by `'self'`), `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. The container SHALL
NOT send `Cross-Origin-Opener-Policy: same-origin`.

#### Scenario: Receipt polling allowed
- **WHEN** the demo awaits a receipt
- **THEN** the cross-origin fetch to the wallet origin's receipt endpoint is not blocked by CSP

### Requirement: Local development parity
`pnpm dev` SHALL run the demo against the local stack with the same `GIANO_*` names read from a `.env` file, and the
demo SHALL be reachable under its own portless names distinct from the e2e fixture's.

#### Scenario: Demo and fixture side by side
- **WHEN** the e2e fixture and the demo run at the same time
- **THEN** they listen on different ports and different `*.localhost` names, and the Playwright suite still drives the
  fixture
