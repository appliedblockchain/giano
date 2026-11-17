---
"@appliedblockchain/giano-contracts": patch
---

Deploy tooling follow-ups from the #279 review (G42):
- On a mainnet, `contracts:provision` needs all six `ROLE_HOLDER_*`, each a different address.
- The chain prerequisite check reports Cancun as unavailable only when the EVM refuses the probe. A rate limit, a timeout or a rejected request is reported as an RPC failure.
- The records directory follows the activated rehearsal, which checks the RPC is an anvil fork, instead of the `GIANO_REHEARSAL_DEPLOYER` variable alone.
- `handoff` refuses when neither the chain profile nor the deployment record names the timelock's address.
- `handoff --from-block` can't start the role-grant scan after the recorded deployment block.
- `provision:paymaster` checks `--unstake-delay` with the other arguments, before the first transaction.
