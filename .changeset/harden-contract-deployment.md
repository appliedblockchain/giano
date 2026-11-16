---
"@appliedblockchain/giano-contracts": minor
---

The deploy tooling can rehearse a testnet deployment on an anvil fork (`pnpm contracts:rehearse`). A stand-in deployer is accepted only when the RPC reports a fork, and everything a rehearsal writes stays in `deploy/rehearsal/`.

Fixes to the deployment path:
- A paymaster upgrade executed through the timelock is read from the proxy and reconciled into the record, instead of blocking every later plan, provision and verify run.
- A handed-off chain verifies with its timelock as `ROLE_ADMIN`.
- Provisioning takes the sponsorship signer's address and one holder per immediate role. It refuses every-role-on-one-address and a defaulted tenant withdrawal address on a mainnet, and explains its refusal after the hand-off.
- The hand-off checks the timelock's release code, proposers, executors and delays before sending anything. On a mainnet, proposers must be contracts; EIP-7702-delegated EOAs count as keys.
- Chains on the mainnet list are always production chains and can never be treated as testnets.
- `deploy:cli core` runs the wizard's chain prerequisite checks (CreateX codehash, EntryPoint v0.9, Cancun), and `--entry-point` is local-only.
- The doctor checks CreateX and Cancun instead of the Arachnid factory, and reports a chain without a P-256 precompile as informational.
- RPC URLs are printed as their origin only.

The testnet profiles now pin release `v3`.
