## Context

`evaluateSponsorship` treated every call from the wallet to itself as wallet management, so that a user adding a passkey on a new device does not need native token. The wallet's `onlyOwner` accepts a call from the wallet to itself, and several wallet functions run a payload. Three wrappers were found one after another during review (`execute`, `upgradeToAndCall`, `signedStaticCall`).

## Decisions

### D1: A list of allowed functions, not a list of refused ones

A list of refused functions misses the next wrapper. A list of allowed functions refuses it by default. The cost is that a self-administration function added to the wallet later is not sponsored until it is added to the list. That failure is safe: the user is asked to pay gas, and the tenant's balance is not at risk.

The list holds only what the product sends (`packages/wallet-core/src/management/owners.ts`): `addOwnerAddress`, `addOwnerPublicKey` and `removeOwnerAtIndex`.

### D2: `removeLastOwner` is not on the list

It leaves the wallet with no owner. wallet-kit refuses to build it (WM-28). Sponsoring it would only let a user make the tenant pay to lock a wallet.

### D3: An owner function with value is refused

The owner functions are not payable, so `execute(self, 1, addOwnerAddress(x))` always reverts. The decoder carries each call's `value` so the rules can refuse it.

### D4: A plain value transfer to self stays wallet management

Calldata of exactly `0x` reaches only the wallet's empty `receive()`, so it runs no payload. wallet-kit allows it (`packages/wallet-kit/src/self-calls.ts`), and the reference demo uses it as its default sponsored send. Refusing it broke the demo's E2E tests.

### D5: A refused self-call keeps the reason `contract-not-allowed`, under its own rule name

A new reason would need a new JSON-RPC code, wallet copy and a release of the published wallet packages. The decision table records the refusal under the rule `self-calls`, so "why was this refused" has a true answer. The detail message names the refused selector.

### D6: Each call is classified once

`classifyCall` returns `application`, `wallet-management` or `refused-self-call`. The `self-calls`, `wallet-management` and allowlist rules all read that result, so they cannot disagree about a call.

## Risks

- **A wallet upgraded to a non-canonical implementation** can redefine any function, so no calldata rule holds for it. This exists on main. The fix is an on-chain implementation check in the paymaster (G40).
- **`initCode` is not signed** by the sponsorship authorisation, so a factory check in wallet-api can be bypassed. Also G40.

## Open Questions

- Should a plain value transfer to self stay wallet management? Today any signed-in user can repeat it, sponsored, with nothing in the tenant's allowlist. It is recorded with `isWalletManagement` and the platform cap, so it mixes into the wallet-management spend figures. A tenant can only refuse it by setting `walletManagement.enabled: false`, which also stops sponsoring owner changes. The alternative is a separate tenant opt-in for self-sends. This is a policy decision for the tech lead, and a follow-up change.
