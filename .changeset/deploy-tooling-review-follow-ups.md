---
"@appliedblockchain/giano-contracts": patch
---

Deploy tooling follow-ups from the #279 review (G42):
- On a mainnet, provisioning needs all six role holders, each a different address and none of them the operator key, and an unstake delay of at least a day. `provision:paymaster` checks this too when run directly, not only the `contracts:provision` wrapper.
- `--unstake-delay` accepts durations (`90`, `6h`, `1d`) and is checked with the other arguments, before the first transaction.
- The chain prerequisite check reports Cancun as unavailable only when the node says an opcode is missing. A rate limit, a timeout, a rejected request or a revert is reported as an RPC failure.
- The records directory follows the activated rehearsal, which checks the RPC is an anvil fork, instead of the `GIANO_REHEARSAL_DEPLOYER` variable alone.
- `handoff` refuses when neither the chain profile nor the deployment record names the timelock's address.
- `handoff --from-block` is checked against the chain: the timelock must have no code before that block. It also can't start after the recorded deployment block.
