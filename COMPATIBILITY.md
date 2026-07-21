# Giano compatibility & upgrade policy

All Giano artifacts ship at **one version** (Changesets fixed mode): the npm packages
(`giano-contracts`, `giano-wallet-core`, `giano-wallet-transport`, `giano-connector`), the
container images (`giano-wallet-api`, `giano-wallet-web`, `giano-bundler`,
`giano-devnet`, `giano-contracts-deployer`) and the Helm chart `appVersion` all carry the
same semver from a single tag.

## Version surfaces

- **npm**: package `version`.
- **wallet-api**: `GET /v1/version` → `{ version, chainId }` (from the `GIANO_VERSION` build arg/env).
- **transport handshake**: the dApp sends `sdkVersion`, the wallet replies `walletVersion` — a
  major mismatch is where a client should warn or refuse.
- **Helm**: `Chart.appVersion` and the image tags.

## Upgrade order

Because each client deploys Giano itself, upgrades are per-deployment. Apply in this order:

1. **wallet-api** (with DB migrations) — migrations are backward-compatible for one minor, so a
   new API serves the old web/SDK during the rollout.
2. **wallet-web** — reads the same API; safe once the API is up.
3. **SDK** (`@appliedblockchain/giano-connector`) in client dApps — last, once the wallet origin
   is on the new version.

Roll back in reverse. Never run a wallet-web/SDK newer than the wallet-api it talks to.

## Compatibility guarantees

- **DB migrations** are additive and backward-compatible across one minor version; a minor
  upgrade never requires simultaneous web/SDK deployment.
- **The transport protocol** is versioned (`giano: <int>` envelope). Within a major, handshake
  capability negotiation keeps older dApps working; a protocol break bumps the envelope integer
  and the package major.
- **Contract bytecode** is frozen per major: any change to compiler settings or sources that
  moves the CREATE2 addresses is a **major** release shipping a new address-registry section
  (the `determinism` CI gate fails the build otherwise).
- **The embedded connector API** (`@appliedblockchain/giano-connector/embedded`) is supported for
  at least two minors after 1.0.0, then removed.
