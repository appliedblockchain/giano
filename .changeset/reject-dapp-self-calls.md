---
"@appliedblockchain/giano-wallet-kit": minor
---

The wallet host now refuses any dApp request that would make the user's account call one of its own functions. Such a self-call can add or remove owners or upgrade the account, so only the wallet's own management view may build one. The check covers `eth_sendTransaction`, `eth_prepareUserOperation`, `eth_signUserOperation` and `eth_sendSignedUserOperation`, including calls inside `execute` and `executeBatch` callData. A value-only transfer to the account (no calldata) is still allowed, and so is a deploy-only user operation (callData `0x`). A dApp that wants the user to manage the wallet calls `giano_openWalletManagement`.

The host also refuses, with error code 4100, a request it cannot check: `params` that is not an array, a transaction, call or user operation that is missing, null or not an object, a `to` or `data` that is not a string, or a user operation whose callData is not an `execute` or `executeBatch` call.

The host runs the check before consent and again after consent, just before the provider runs the request. If no account exists at either point, the host refuses the request with error code 4900, the same code the provider gives. For `eth_signUserOperation`, the host refuses with 4100 a `sender` that is not the connected account, and fills in a missing one. The provider then refuses the request if its account changes before it signs.

New export `checkSelfCall` returns whether a request is a self-call or cannot be checked, so a consent screen can block it as a second layer.
