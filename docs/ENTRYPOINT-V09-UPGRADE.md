# E1: EntryPoint v0.9 upgrade

Giano now targets **EntryPoint v0.9.0**, the latest stable eth-infinitism release checked on
27 October 2026. The canonical address is `0x433709009B8330FDa32311DF1C2AFA402eD8D009`.
This is a breaking protocol change from v0.7, intended for a coordinated release of the contracts,
wallet, API, bundler and deployment configuration. It does not migrate a live deployment by itself.

## What changes

- Wallet signing, API audit/idempotency hashes and bundler hashes use the v0.9 EIP-712 operation
  digest. Previously signed v0.7 operations must be rebuilt and signed again.
- The wallet implementation authorizes the v0.9 address. Its special chain-independent upgrade
  hash retains its separate scheme, but uses the new typed operation struct hash.
- Contract release **v2** freezes the new Cancun build; v1 remains immutable. Canonical CREATE3
  labels and addresses remain the same for fresh deployments. Both baked local-chain states
  are regenerated with the pinned Anvil image; chain B loads its own state because the
  EntryPoint runtime caches the chain ID.
- The estimator runs the final v0.9 simulation code. SenderCreator's immutable caller is bound
  to the canonical EntryPoint. Gas estimates account for the 40,000 unused-gas threshold and
  for prefunding that becomes necessary at the real gas price. Limits and settlement allowances
  are conservative; measure fees with the target chain's real passkey and sponsorship traffic.
- The doctor and bundler compare the canonical runtime, including chain-dependent EIP-712 caches.
  A mainnet runtime hash alone is insufficient: the constructor embeds a chain ID and domain.
- All workspace viem consumers and the standalone example use 2.57.11, which understands v0.9.
  The wallet-core peer floor is raised accordingly. Contracts and wallet-core carry a major changeset.
  The standalone example consumes published Giano packages; update those package versions after
  the coordinated major release is published before using it against v0.9.

The final v0.9 source is pinned to upstream commit
`b36a1ed52ae00da6f8a4c8d50181e2877e4fa410`. npm's stable contracts package was still 0.8.0
when checked; its 0.9.0-rc.1 differs from the final release in validation/security behavior.
The final source, verified canonical EntryPoint artifact, and reproducible simulation input are
therefore vendored. See [artifact provenance and rebuild instructions](../packages/contracts/vendor/account-abstraction/README.md).

## Chain support

A chain must implement Cancun EVM semantics, including `PUSH0`, `MCOPY`, `TLOAD` and `TSTORE`,
provide `basefee`, and have the exact canonical EntryPoint and SenderCreator. The RPC must support
`eth_call` state overrides and `eth_estimateGas`. Giano additionally needs CreateX, its canonical
contracts, usable P-256 verification (precompile or the supported fallback), funding, and a passing
[chain-adoption checklist](../specs/CHAIN-ADOPTION.md).

The following records were queried from Sourcify on 27 October 2026. Each had exact creation/runtime
verification. The retrieved runtime also matched Giano's expected v0.9 runtime after reconstructing
its chain-dependent EIP-712 cache. These are verification records, not fresh public-network transaction
or RPC-capability tests. The v0.9 address is identical in every row.

| Chain | ID | EntryPoint evidence | Giano status after this change |
| --- | --- | --- | --- |
| Local Anvil A / B | 31337 / 31338 | Canonical deployment from verified creation code | Automated integration target; baked development states |
| Ethereum Sepolia | 11155111 | [Exact verification](https://sourcify.dev/server/v2/contract/11155111/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Testnet adoption target; deployment and acceptance still required |
| Base Sepolia | 84532 | [Exact verification](https://sourcify.dev/server/v2/contract/84532/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Testnet adoption target; deployment and acceptance still required |
| Base | 8453 | [Exact verification](https://sourcify.dev/server/v2/contract/8453/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Candidate; OP-stack L1 fee path exists; adoption required |
| Ethereum | 1 | [Exact verification](https://sourcify.dev/server/v2/contract/1/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Candidate; adoption required |
| OP Mainnet | 10 | [Exact verification](https://sourcify.dev/server/v2/contract/10/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Candidate; OP-stack L1 fee path exists; adoption required |
| Arbitrum One | 42161 | [Exact verification](https://sourcify.dev/server/v2/contract/42161/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | EntryPoint-compatible candidate; qualify Arbitrum fee accounting before support |
| Polygon PoS | 137 | [Exact verification](https://sourcify.dev/server/v2/contract/137/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Candidate; native-currency configuration and adoption required |
| BNB Smart Chain | 56 | [Exact verification](https://sourcify.dev/server/v2/contract/56/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Candidate; native-currency configuration and adoption required |
| Avalanche C-Chain | 43114 | [Exact verification](https://sourcify.dev/server/v2/contract/43114/0x433709009B8330FDa32311DF1C2AFA402eD8D009) | Candidate; native-currency configuration and adoption required |

**No public chain becomes a production-supported Giano deployment merely by merging this PR.**
The committed public Giano registry is empty and the canonical deployer is still a placeholder.
Sepolia and Base Sepolia are the next acceptance targets; Base is the existing production adoption
candidate. Other EVM chains may qualify through the same checklist. Pre-Cancun chains and native
non-EVM account-abstraction systems are outside this implementation's compatibility guarantee.

## Existing deployments and rollout

1. Inventory existing account implementations, immutable factory implementation addresses, paymaster
   configuration, EntryPoint deposits/stakes, pending operations, and external bundler capabilities.
   Keep the old stack available while draining v0.7 operations.
2. Existing wallets keep their v0.7 EntryPoint binding until each owner authorizes a UUPS upgrade
   to the new implementation. The old factory's immutable implementation does not change when a
   release is cut. A live factory/new-account migration needs its own address-preservation design;
   do not assume deploying v2 replaces code already occupying canonical addresses.
3. The sponsorship paymaster stores its EntryPoint in proxy storage at initialization and has no
   setter. Updating implementation bytecode does not change that pointer. A live migration needs
   an explicitly reviewed storage/deposit migration or a new paymaster deployment, with ledger
   conservation and tenant funding accounted for. EntryPoint deposits and stakes do not move
   between versions automatically; respect stake unlock delays.
4. For fresh chains, deploy v2, provision and fund sponsorship against v0.9, run the doctor, then
   atomically update the wallet/API/bundler/configuration. Configure third-party bundlers only if
   `eth_supportedEntryPoints` includes v0.9; ABI compatibility alone does not establish service support.
5. Accept the chain only after real first-account creation, self-funded and sponsored passkey
   operations, revert handling, receipts, nonce replay rejection, and executor/paymaster economics
   pass on its actual RPC. Retire the old stack only after migration acceptance.

## Feature boundaries

Giano continues to use factory-deployed passkey wallets and its existing sponsorship authorization.
This upgrade does **not** add an EIP-7702 account flow, parallel `paymasterSignature` signing, or
block-number validity configuration. Explicit 7702/parallel-signature request fields are rejected
instead of silently stripped. The reference EntryPoint implements these optional features; adopting
them needs additional wallet, paymaster and API work. Giano's bundler remains a direct submission
service, rather than a public ERC-7562 mempool implementation.

v0.9 also ignores `initCode` once an account exists. Giano's factory initialization remains guarded;
application code must not treat nonempty initCode as proof that this is the account's first operation.
The new outer-call rule requires the bundler executor to be an EOA (`tx.origin == msg.sender`, no code).
Contract-based executor accounts are incompatible with that rule.

## Validation

Local validation completed:

- 180 Solidity tests, including sponsored Giano wallet execution and accounting invariants.
- 377 package tests, 44 bundler tests, and 406 wallet API tests.
- Full workspace typecheck, package builds, Biome, Dockerfile policy and chain-document tests.
- Canonical v2 hashes, both pinned-Anvil devnet generators and their doctor checks.
- v1/v2 release reproduction and final upstream creation/simulation artifact reproduction.
- Bundler Docker build and container smoke test: both baked chains report ready with v0.9.

The PR's CI results provide the clean-runner checks. Local tests do not substitute for public-chain
adoption or a production security review. The deterministic v2 release and upstream simulation
artifacts are reproducible from committed standard JSON inputs.

## Primary references

- [Final v0.9 release and changes](https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.9.0)
- [Pinned v0.9 implementation](https://github.com/eth-infinitism/account-abstraction/tree/b36a1ed52ae00da6f8a4c8d50181e2877e4fa410)
- [Verified mainnet source and bytecode](https://sourcify.dev/server/v2/contract/1/0x433709009B8330FDa32311DF1C2AFA402eD8D009?fields=all)
- [EIP-1153 transient storage](https://eips.ethereum.org/EIPS/eip-1153)
- [Parallel paymaster signatures](https://docs.erc4337.io/paymasters/paymaster-signature.html)
