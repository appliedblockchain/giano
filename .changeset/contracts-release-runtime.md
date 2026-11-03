---
"@appliedblockchain/giano-contracts": minor
---

Each release records `GianoPaymaster`'s runtime codehash, with its immutables zeroed, and where those immutables are. `paymasterReleaseOf(code)` and `PAYMASTER_RELEASES` (from the new `releases.ts`) tell which release the code at a paymaster implementation is, whatever address it was deployed at. `timelockedRoleProblems` and `delayShortfalls` judge a timelock's role topology and delays against the published policy, for `giano-doctor` and the SDK's `assessHealth` alike.
