---
"@appliedblockchain/giano-contracts": minor
---

`timelockedRoleProblems` and `delayShortfalls` judge a timelock's role topology and delays against the published policy, for `giano-doctor` and the SDK's `assessHealth` alike.

`parseDelayList` parses a `minDelay=2d,upgradeToAndCall=7d,…` flag, as `giano-doctor` and the SDK's CLI take it.
