# Fixture artifacts

Test fixtures the deploy CLI deploys from a committed artifact instead of a release
(`deploy/fixtures.ts`).

- `private-test-erc20.json`: the private test token `GianoTestPrivateErc20`
  (`src/testing/GianoTestPrivateErc20.sol`, on UCEF from the `lib/ucef-contracts` git submodule). It
  holds the creation code, the runtime code, its size and the fingerprint (keccak256 of the runtime
  code; the token has no immutables).

Why not a release: a release is what every chain of a class is adopted at, forever. The token exists
only for the demo's private token section (openspec `silent-data-network`, design D7), so it must not
wait for a release, and a release must not carry it.

Regenerate with `pnpm gen:fixtures` after a change to the token, to UCEF or to the build settings, and
commit the result. CI (`pnpm gen:fixtures --check`) fails when the artifact does not match the source.

`deploy:cli testing` and `local:deploy` deploy the token from here, so the deployer image ships this
directory (`Dockerfile.deployer`). A deployment record names its release as `fixture` and carries the
artifact's fingerprint, which `gen:addresses` checks.

A chain keeps the code it was deployed with, and the token's address depends only on its label. So
when the code changes, `pnpm gen:fixtures` moves the committed artifact's fingerprint to `previous`
(newest first). A chain that holds an earlier version still passes `gen:addresses` and a re-run of
`testing`; a new chain gets the current code. The artifact it replaces is the one at git HEAD, so
running the generator again before a commit adds no version that was never committed.

The token's `totalSupply()` is public (UCEF). Every mint changes it, so comparing it before
and after a block shows the amounts minted, and while one account holds the whole supply, it is that
account's balance. Only `balanceOf`, `allowance` and the transfer and approval events are private.
