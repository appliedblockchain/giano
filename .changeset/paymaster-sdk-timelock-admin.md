---
"@appliedblockchain/giano-paymaster-sdk": minor
---

`GianoTimelockClient` proposes changes to the timelock itself: `proposeUpdateDelay`, `proposeSetFunctionDelay`, `proposeGrantTimelockRole` and `proposeRevokeTimelockRole`, built on a new public `timelockCall`. `cancelCalldata(id)` encodes a cancel from the id alone, for an operation whose scheduling is older than the blocks read.
