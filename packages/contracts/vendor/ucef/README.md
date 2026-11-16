# UCEF

Unmodified sources of UCEF (Unopinionated Confidential ERC-20 Framework), from
[appliedblockchain/ucef-contracts](https://github.com/appliedblockchain/ucef-contracts), commit
`03913b199109c029cfe24f5dce8b54b7186dbc45` (`packages/ucef/contracts/`). MIT; see `LICENSE`.

| File | Upstream path | SHA-256 |
|---|---|---|
| `UCEF.sol` | `packages/ucef/contracts/UCEF.sol` | `a546cc913de1f5319278ade513f1d3090c035d9fc06583369cb8c47754bf2a25` |
| `UCEFOwned.sol` | `packages/ucef/contracts/UCEFOwned.sol` | `7010c321f6632e80cb465ed5ee96b2435088e66b0b3f784971e8fefa2cdc8711` |
| `utils/PrivateEventEmitter.sol` | `packages/ucef/contracts/utils/PrivateEventEmitter.sol` | `797af43ea2ad7523943f122c256f85a0f83540b3b31b0ef65c9684a54ee117d9` |

These are the files `UCEFOwned` needs: it imports `UCEF.sol`, which imports
`utils/PrivateEventEmitter.sol` and OpenZeppelin's `ERC20` (from `node_modules/@openzeppelin`, as for
every Giano contract). Neither imports anything under upstream `interfaces/`. The upstream layout is
kept, so the relative imports are unchanged.

Only the test token `src/testing/GianoTestPrivateErc20.sol` uses them (openspec change
`silent-data-network`, design D7). They are copied rather than added as a Forge library because
`ucef-contracts` is an organisation repository, and a submodule would need repository access in CI.

To update: copy the same files from a newer commit, update the commit and the hashes above, and
cut a new release before deploying the result.
