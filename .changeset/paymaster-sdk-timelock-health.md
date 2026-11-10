---
"@appliedblockchain/giano-paymaster-sdk": minor
---

`assessHealth(overview, context)` takes the paymaster's timelock and the code at its implementation. With a timelock, it checks that the timelock alone holds the four timelocked roles and that no delay is below its published value; without one, a single warning says no timelock is configured, in place of the "verify this is the timelock" warning on each role. The implementation is matched to a contracts release, and code that is no release fails. `getHealth()` passes the implementation itself and takes the timelock; `getImplementationCode()` and `timelockDelays(config)` supply the rest.

Given expected delays that leave a name out, the delay check warns and names each one rather than passing it. An implementation that matches no release names the newest release the SDK knows, so a newer release reads as an SDK to update. `readImplementationSlot()` reads the ERC-1967 slot without throwing on an empty one. The CLI's `health` checks the timelock with `--timelock`, against `--timelock-delays` when given.
