---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
"@appliedblockchain/giano-connector": minor
---

Require a connection before a dApp can read or use the wallet account. Before, any origin in `allowedDappOrigins` could open the popup and call `giano_restoreAccount`, `eth_accounts` or `eth_prepareUserOperation` with no consent screen. It got the user's address, and `eth_prepareUserOperation` made the paymaster issue a signed authorisation and reserve tenant balance until the reservation expired.

The `giano-wallet-kit` host now keeps a connection grant for each dApp origin in the wallet origin's `localStorage`. It records the grant when the user approves `eth_requestAccounts` and the provider returns an account. `wallet_revokePermissions` from that origin removes the grant. An origin with no grant gets `[]` from `eth_accounts` and EIP-1193 `4100` from every method that uses the account: `eth_sendTransaction`, `personal_sign`, `eth_sign`, `eth_signTypedData_v4`, `eth_signUserOperation`, `signed_eth_call`, `eth_prepareUserOperation` and `eth_sendSignedUserOperation`. The host checks the grant before it restores the account, so a refused origin never receives an `accountsChanged` event. The host refuses `giano_restoreAccount` from an application with `4200`.

The `giano-wallet-core` provider no longer passes an unknown method to its node. It passes only the read-only chain methods in the new `READ_ONLY_RPC_METHODS` export, and refuses any other method it does not implement with EIP-1193 `4200`. An integration that sent a write or node method, such as `eth_sendRawTransaction`, through the provider must now send it to its own RPC client.

A dApp that already connected before this release has no grant yet. Its next account request gets `4100`, and it must call `eth_requestAccounts` again once. The `giano-connector` provider now treats `4100` from the wallet like `4900`: it drops its cached session and emits `accountsChanged` with `[]` and `disconnect`, so the dApp shows the user as disconnected instead of connected with every action failing.
