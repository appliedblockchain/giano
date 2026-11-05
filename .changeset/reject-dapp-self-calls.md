---
"@appliedblockchain/giano-wallet-kit": minor
---

The wallet host now refuses any dApp request that would make the user's account call one of its own functions. Such a self-call can add or remove owners or upgrade the account, so only the wallet's own management view may build one. The check covers `eth_sendTransaction`, `eth_prepareUserOperation`, `eth_signUserOperation` and `eth_sendSignedUserOperation`, including calls inside `execute` and `executeBatch` callData. A value-only transfer to the account (no calldata) is still allowed. The host also refuses a user operation whose callData is not an `execute` or `executeBatch` call, because its calls cannot be checked. Both refusals use error code 4100 and happen before any consent screen. A dApp that wants the user to manage the wallet calls `giano_openWalletManagement`.

New export `checkSelfCall` returns whether a request is a self-call, so a consent screen can block one as a second layer.
