---
'@appliedblockchain/giano-paymaster-admin': minor
---

Connecting a wallet on a chain the console does not administer used to end at "Switch networks and
reconnect", with nothing in the console that could switch anything — an operator had to find the
network in their wallet's own menus, and on a console that administers two chains they had to do it
again every time they moved between them. Connect now moves the wallet itself: it asks for the
deployment's chain, adds the network when the wallet has never seen it, and connects. The wallet
still raises its own prompt naming the network, and the console only ever asks for a chain that is
already in its configured list.

**New (image contract):** `walletRpcUrl` on a deployment, `GIANO_WALLET_RPC_URL` for the
single-deployment shorthand — the address to hand a wallet that has to add the network itself. It is
stated rather than derived because `rpcUrl` is normally `/rpc/<chainId>`, a proxy path no wallet can
dial, and behind it a keyed provider endpoint that must not be published to every operator's wallet.
Optional: without it the console offers `rpcUrl` and reports what the wallet says if it refuses. It
is passed through unproxied and stays out of `connect-src`, since the page never dials it.

A wallet that will not add a network — hardware and custody wallets do not, and MetaMask rejects any
RPC URL that is not HTTPS or literal localhost — is answered with the network's details to add by
hand rather than a raw provider error. Those errors are now read out of the serialised
`{ code, message }` object a wallet actually rejects with, so they no longer reach the operator as
`[object Object]`; the same applies to every error toast in the console.

The header labels its two addresses instead of showing two bare hex strings, and a connected wallet
is a panel in the connect button's place giving the account, the network it is on and the roles it
holds on this paymaster.
