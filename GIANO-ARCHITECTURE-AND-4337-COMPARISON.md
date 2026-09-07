# Giano — Architecture Report and Comparison with ERC-4337

**Repository:** `appliedblockchain/giano`
**Branch analysed:** `main` @ `5bbbd99` ("fix: do not allow pending accounts to call execute")
**Contracts version:** `@appliedblockchain/giano-contracts` 2.0.1
**Date:** 2026-08-25

---

## 0. A note on the working tree

Before anything else: the checkout contains a large amount of **build residue from a different branch**. These directories exist on disk but hold only `dist/` and `node_modules/` — no source, and nothing tracked by git:

```
packages/connector   packages/paymaster-sdk   packages/wallet-core   packages/wallet-transport
services/custom-example   services/paymaster-admin   services/wallet-api   services/wallet-web
```

Likewise `packages/contracts/typechain-types/` and `packages/contracts/artifacts/` on disk contain generated bindings for contracts that **do not exist on this branch** (`GianoSmartWallet`, `MultiOwnable`, `AuthenticatedStaticCaller`, `paymaster/…`), and `vendor/`, `e2e/`, `packages/contracts/lib/`, `out/`, `cache_forge/` are untracked. Anyone reading the tree with `ls` will conclude Giano is an ERC-4337 wallet with a bundler, a paymaster SDK and a two-origin popup architecture. **On `main`, none of that is present.**

What is actually tracked is small and coherent:

| Unit | Package | Content |
|---|---|---|
| `packages/contracts` | `@appliedblockchain/giano-contracts` | 8 Solidity sources (~1,200 LoC) + Hardhat/Ignition + 2,900 LoC of Mocha tests |
| `packages/common` | `@appliedblockchain/giano-common` | WebAuthn assertion → ABI encoding helpers |
| `packages/client` | `@appliedblockchain/giano-client` | `GianoWalletClient` — an ethers contract proxy |
| `services/web` | `@appliedblockchain/giano-web` | React + MUI demo (client only) |

Everything below describes that tracked code.

---

## 1. What Giano is

Giano is a **passkey-native smart contract wallet**. A user's identity is a WebAuthn credential (a secp256r1/P-256 passkey held by the OS or a hardware authenticator). There is no seed phrase, no EOA, no browser extension. The user's on-chain account is a contract that verifies P-256 WebAuthn assertions natively, and any transaction the user authorises is a signed *intent* that a third party submits and pays for.

The README calls it "a limited account abstraction mechanism", and that phrase is the key to reading the whole design: Giano implements the *outcomes* of account abstraction — passkey signers, sponsored gas, batching, role-scoped keys — **without adopting ERC-4337**. There is no `EntryPoint`, no `UserOperation`, no `validateUserOp`, no bundler, no paymaster contract anywhere in the tracked source. It is a self-contained, standalone design.

---

## 2. The contracts

Eight Solidity files, all `pragma ^0.8.23`, compiled with optimizer runs 200 and `viaIR`.

```
AccountRegistry.sol      global credential ↔ account index; entry point for account creation
AbstractAccountFactory   deployment interface
AccountFactory.sol       CREATE2 deployer for Account
Account.sol              the wallet itself (746 LoC — the core of the system)
WebAuthn.sol             WebAuthn assertion verification
P256.sol                 secp256r1 signature verification
Base64.sol               Base64URL encoding (needed to rebuild the challenge string)
Types.sol                shared structs
```

### 2.1 Signature verification — the foundation

Everything rests on being able to check a WebAuthn assertion on-chain. The chain is:

```
Account._validateSignature
   └── WebAuthn.verifySignature
         ├── authenticatorData flags check   (UP bit; UV optional; BE/BS consistency)
         ├── clientDataJSON contains  "type":"webauthn.get"     at responseTypeLocation
         ├── clientDataJSON contains  "challenge":"<b64url>"    at challengeLocation
         └── P256.verifySignatureAllowMalleability(
                 sha256(authenticatorData ‖ sha256(clientDataJSON)), r, s, x, y)
                   └── staticcall → 0xc2b78104907F722DABAc4C69f826a522B2754De4
```

The `challengeLocation` / `responseTypeLocation` trick is what makes this affordable: rather than parsing JSON on-chain, the client tells the contract *where* to look and the contract only does a byte-compare at that offset.

The P-256 verifier address is the **deterministic deployment of the Daimo `p256-verifier`**, a pure-Solidity implementation of RIP-7212. `scripts/p256_deploy.ts` deploys it to that exact address on any new chain via the canonical CREATE2 factory (`0x4e59b448…`), first bootstrapping that factory from a pre-signed raw transaction if it is absent. On chains where the RIP-7212 precompile exists natively the verification is cheap (order of a few thousand gas); on chains where the Daimo fallback is used it is expensive (roughly two orders of magnitude more). `hardhat.config.ts` sets `enableRip7212: true` for `hardhat`/`localhost`, and the Ignition module additionally `hardhat_setCode`s the verifier bytecode at that address on chain 31337 so local tests exercise the same path.

### 2.2 `Account` — the wallet

A single non-upgradeable contract, deployed once per user, implementing `IERC1271`, `IERC721Receiver`, `IERC1155Receiver`, `ReentrancyGuard`.

**Credential model.** `mapping(bytes => CredentialInfo) credentials`, where a credential is `{credentialId, PublicKey{x,y}, Role, pending}`. Roles form a strict ladder:

| Role | Value | Can do |
|---|---|---|
| `NONE` | 0 | nothing (also means "does not exist") |
| `EXECUTOR` | 1 | `execute`, `executeBatch`, `isValidSignature` |
| `ADMIN` | 2 | everything above + all admin operations |

`_hasRole` requires `role >= minimum && !pending`. The `!pending` clause is the most recent commit on the branch — a pending credential is stored on-chain but must not act until approved.

**Credential lifecycle.** Adding a signer is a two-step, two-party flow:

```
1. anyone → AccountRegistry.requestAddCredential(credentialId, account, pubKey, role)
2. registry → Account.requestAddCredential(...)          // stored with pending = true
3. an ADMIN signs an AdminAction and calls approveCredentialRequest / rejectCredentialRequest
4. on approval → pending = false; adminKeyCount++ if ADMIN; registry.notifyCredentialAdded
```

This is what "multiple signers support" (`d7cc294`) delivers: a phone passkey can *request* to join an account, and an existing admin device *approves* it. The invariant `adminKeyCount >= 1` is enforced on both `removeCredential` and `changeCredentialRole`, so an account cannot be bricked by removing its last admin.

**Two separate authorisation paths, two separate nonces.**

```
                       challenge preimage                              nonce
execute        keccak256(this ‖ currentNonce ‖ target ‖ value ‖ data)   currentNonce
executeBatch   keccak256(abi.encode(this, currentNonce, callHashes))    currentNonce
admin ops      keccak256(this ‖ operation ‖ operationData ‖ nonce)      adminNonce
```

Admin operations additionally require `keccak256(operationData)` to equal the encoding of the function's own arguments — so the signature is bound not just to the operation *type* but to its exact parameters. `adminNonce` and `currentNonce` are independent `uint64`s packed with `adminKeyCount` into one slot.

**Execution.** `execute(SignedCall)` and `executeBatch(BatchCall)` are `external payable`, `nonReentrant`, `whenNotPaused`. Both are callable **by anyone** — authorisation is entirely in the WebAuthn signature over the nonce-bound challenge, never in `msg.sender`. Reverts from the target are bubbled up verbatim via inline assembly. The batch variant is all-or-nothing and increments the nonce once for the whole batch.

**Pause.** An admin can pause the account until a timestamp (`0` → `type(uint256).max`, i.e. indefinitely), blocking `execute`/`executeBatch` while leaving admin operations available — so a user who suspects a compromised device can freeze the account and then remove the credential.

**ERC-1271.** `isValidSignature(hash, sig)` runs the same `_validateSignature` and returns the magic value, letting the account sign EIP-712 payloads for off-chain consumers. The demo shows the round trip: sign typed data with a passkey, then have a "backend" verify it against the contract.

### 2.3 `AccountRegistry` and `AccountFactory`

The registry is a global directory enforcing **one credential → at most one account**:

```
mapping(address => User)  users              // account → initial credential
mapping(bytes => address) credentialToAccount
mapping(address => bool)  registeredAccounts
```

`createUser(credentialId, publicKey)` calls the factory, records the account, and links the credential. Accounts call back into `notifyCredentialAdded` / `notifyCredentialRemoved` (gated by `onlyRegisteredAccount`) so the global index tracks per-account credential changes.

The factory deploys with `new Account{salt: keccak256(abi.encode(publicKey, credentialId, registry))}`, and `computeAccountAddress` reproduces the CREATE2 computation. So **an account address is a pure function of its initial passkey**, derivable before deployment — the address is counterfactual and can be funded in advance.

Note that `Account` is deployed directly, not behind a proxy, and has no upgrade mechanism.

---

## 3. The client stack

### 3.1 `@appliedblockchain/giano-common` — `encodeChallenge`

The bridge between the browser and the contract. Given an `AuthenticatorAssertionResponse`, it:

1. decodes `clientDataJSON` and finds the byte offsets of `"type":` and `"challenge":`;
2. parses the DER-encoded ECDSA signature with `@peculiar/asn1-ecc` and lifts `r`, `s` to `uint256`;
3. ABI-encodes the whole thing as the `Types.Signature` tuple.

The offset-finding in JS is precisely what lets the Solidity side skip JSON parsing.

### 3.2 `@appliedblockchain/giano-client` — `GianoWalletClient`

A small, rather elegant piece of DX. `proxyFor(contract)` returns a `Proxy` over any ethers contract that leaves `view` functions untouched but rewrites every state-changing call into `.send()`, which:

```
encodeFunctionData(fn, args)
  → account.getChallenge({target, value, data})     // read the nonce-bound challenge
  → challengeSigner(challenge)                      // navigator.credentials.get(...) → encodeChallenge
  → account.execute({ call, signature })            // submitted by whatever signer is attached
```

It also re-parses revert data through the *target's* ABI, so a revert inside the inner call surfaces as a named custom error instead of an opaque `CALL_EXCEPTION`. Calling code reads as:

```ts
await tokenProxy.transferFrom(user.account, recipient, tokenId).send();
```

### 3.3 `services/web` — the demo

React 18 + MUI + Vite. `Login.tsx` creates a passkey (`ES256`, resident key required, `userVerification: 'required'`) and registers it; `Wallet.tsx` mints/transfers ERC-721 and ERC-20 through the proxy, runs a faucet, and demonstrates the EIP-712 + ERC-1271 flow. Session state (account address, `rawId`, credentialId) lives in `sessionStorage`.

**The demo is stale relative to the 2.0 contracts and will not run as written.** `Login.tsx` calls `AccountFactory__factory.connect(...).createUser(userId, {x, y})` and `.getUser(userId)` — but on this branch `createUser`/`getUser` live on `AccountRegistry`, not `AccountFactory`, and take `bytes credentialId` rather than a `uint256` derived from `rawId.slice(-32)`. `Wallet.tsx` calls `encodeChallenge(credential.response)` with one argument where the 2.0 signature is `encodeChallenge(credentialId, assertionResponse)`. The README also still points at `Account.sol`/`AccountFactory.sol` as "the" contracts and describes a `yarn`-based workflow, and `package.json` has `web:start` pointing at `src/server/index.ts`, which does not exist. The demo tracks the v1 API; the contracts moved on.

Also, and only worth stating because it is easy to copy by accident: both `Login.tsx` and `Wallet.tsx` hardcode the well-known Hardhat account #0 private key and hardcoded contract addresses, and connect over `ws://localhost:8545`. That is the relayer stand-in for local development, and it is the piece a real deployment has to replace with an actual relayer service.

---

## 4. End-to-end flow

```
┌─ Registration ──────────────────────────────────────────────────────────┐
│ navigator.credentials.create({ES256, residentKey, uv:'required'})       │
│   → CBOR-decode attestation → authData → COSE key → (x, y)              │
│ AccountRegistry.createUser(credentialId, {x,y})                         │
│   → AccountFactory.deployAccount  (CREATE2, salt = H(pubKey,credId,reg))│
│   → Account deployed with that credential as ADMIN, adminKeyCount = 1   │
└─────────────────────────────────────────────────────────────────────────┘

┌─ Transaction ───────────────────────────────────────────────────────────┐
│ challenge = Account.getChallenge({target, value, data})   (view call)   │
│ navigator.credentials.get({challenge, allowCredentials:[rawId]})        │
│   → OS prompts biometric → assertion (authenticatorData, clientDataJSON,│
│                                       DER signature)                    │
│ encodeChallenge(credentialId, assertion) → Types.Signature (ABI)        │
│ relayer EOA → Account.execute({call, signature})     ← relayer pays gas │
│   → _validateSignature → WebAuthn.verifySignature → P256 verifier       │
│   → target.call{value}(data);  currentNonce++                           │
└─────────────────────────────────────────────────────────────────────────┘
```

The user never holds ETH and never signs an Ethereum transaction. They sign a 32-byte challenge with a fingerprint; someone else pays.

---

## 5. Comparison with ERC-4337

### 5.1 The two architectures side by side

**ERC-4337:**

```
 user ──signs──> UserOperation ──> alt-mempool ──> Bundler ──> EntryPoint (singleton)
                                                                  │
                                          ┌───────────────────────┼──────────────────┐
                                     validateUserOp        validatePaymasterUserOp   │
                                     (your account)          (paymaster)             │
                                          └───────────────────────┼──────────────────┘
                                                          account.execute(...)
                                                          gas accounting / refund
```

**Giano:**

```
 user ──signs──> SignedCall ──> your relayer (private) ──> Account.execute() ──> target
```

ERC-4337 inserts a shared, standardised singleton between the user and their account. Giano removes the middle entirely: the account *is* the entry point, and the transport is whatever you build.

### 5.2 Feature comparison

| Dimension | Giano (as on `main`) | ERC-4337 |
|---|---|---|
| **Standard** | Bespoke. Only ERC-1271/165/721/1155 receivers are standard | ERC-4337 (+ ERC-7677 paymaster RPC, ERC-7579/6900 modules) |
| **Entry point** | None — call `Account.execute` directly | Audited singleton `EntryPoint` (v0.7 at `0x0000000071727De22E5E9d8BAf0edAc6f37da032`) |
| **Op format** | `SignedCall{Call, signature}` | `PackedUserOperation` |
| **Who submits** | Any EOA; you must run the relayer | Bundler network (Pimlico, Alto, Stackup, Biconomy, …) or your own |
| **Gas sponsorship** | Implicit: the relayer pays, unconditionally | Explicit `Paymaster` with EntryPoint deposit/stake, `validatePaymasterUserOp` + `postOp`, ERC-20 and verifying paymasters |
| **Relayer reimbursement** | **None.** No mechanism for the account to repay the submitter | EntryPoint prefunds from account/paymaster deposit and refunds unused gas |
| **Nonce** | Two sequential `uint64`s (tx + admin) | 2-D `(key, sequence)` — parallel/independent op lanes |
| **Chain-ID binding** | **Absent** from the execute challenge | `userOpHash` commits to `chainId` and the EntryPoint address |
| **Deployment** | Separate `createUser` tx, paid by whoever calls it, *before* first use | `initCode`/`factory` in the first UserOp — deploy + first action atomic and sponsorable |
| **Counterfactual address** | Yes (`computeAccountAddress`) | Yes (`getSenderAddress`) |
| **Batching** | `executeBatch`, one user | `executeBatch` per account **and** bundler-level batching across users → amortised base cost |
| **Passkey / P-256** | First-class, the only signer type | Requires a custom account or validator module (Coinbase Smart Wallet, Kernel, Safe passkey module…) |
| **Signer roles** | **Built in**: `EXECUTOR`/`ADMIN`, request→approve onboarding, pause | Not in the standard; needs ERC-7579/6900 modules or a custom validator |
| **Upgradeability** | **None** — `Account` is a direct CREATE2 deployment | Nearly all implementations are proxies (ERC-1967/UUPS) |
| **Sig aggregation** | No | `IAggregator` (e.g. BLS) |
| **Anti-DoS for infra** | Your problem — you simulate before relaying | Staking + reputation rules for factories/paymasters/aggregators; bundler validation rules |
| **Ecosystem/tooling** | Custom SDK only | `viem/account-abstraction`, `permissionless`, wagmi connectors, jiffyscan, bundler & paymaster RPC standards |
| **Per-op gas overhead** | Lower — one `call` into your account, no EntryPoint bookkeeping | Higher — EntryPoint validation loop, deposit accounting, refunds |
| **On-chain surface to audit** | ~1,200 LoC, all yours | Your account (small) + a heavily audited shared singleton |

### 5.3 Where Giano genuinely wins

- **Simplicity and gas.** A Giano transaction is one external call into your own contract. There is no EntryPoint validation loop, no deposit accounting, no refund pass. For a single user's single call, Giano is meaningfully cheaper and much easier to reason about.
- **A tiny, self-owned surface.** Eight files. You can read the whole authorisation path in an afternoon. No dependency on a singleton's semantics, no bundler validation rules to satisfy, no `AA24`-class errors to debug.
- **Roles, onboarding and pause are native.** This is the strongest point. `EXECUTOR`/`ADMIN`, the request→approve credential flow, `adminKeyCount >= 1`, and time-bounded pause are *in the account*, expressed directly and covered by 2,900 lines of tests. Getting the equivalent under ERC-4337 means adopting ERC-7579 or ERC-6900 and composing validator/hook modules — considerably more machinery, and the multi-device approval flow in particular is not something you get off the shelf.
- **No third-party liveness dependency.** No bundler, no alt-mempool, no paymaster deposit to keep topped up. If your relayer runs, the wallet works.
- **Deployable anywhere.** Two contracts plus the Daimo verifier. It works on any EVM chain, including ones with no bundler infrastructure and no deployed EntryPoint — which is a real advantage on appchains and private/consortium networks.

### 5.4 Where ERC-4337 genuinely wins

- **Someone else runs the infrastructure.** Giano's relayer is a hand-wave in the demo (a hardcoded Hardhat key). In production it becomes a service you must build, fund, monitor, rate-limit, protect against abuse, and simulate against — because nothing reimburses it and nothing stops a user from submitting an op that burns gas and reverts. ERC-4337 turns that into a solved, competitive, commodity market.
- **Economics are specified.** Paymasters, deposits, stake, `postOp`, refunds, ERC-20 gas payment, ERC-7677 sponsorship RPC. Giano has *sponsorship* (the relayer eats it) but no *economics* — no way to charge the user, no way for the account to repay the submitter, no policy layer.
- **Interoperability.** A 4337 account is understood by wallets, SDKs, explorers and indexers. Giano's `Executed(nonce, target, value, data)` event and bespoke calldata mean every integration is custom work.
- **Atomic deploy-and-act.** Under 4337 a brand-new user's very first sponsored UserOperation deploys the account and does the thing. Under Giano, `createUser` is a separate transaction that someone must pay for first, before the account can be used at all.
- **Parallelism.** The 2-D nonce lets independent operations proceed concurrently. Giano's single sequential `currentNonce` serialises everything, and a signed-but-unsubmitted call invalidates every later signature — awkward for anything that pre-signs or queues.
- **Bundler-level batching.** Amortising the 21,000-gas base cost across many users' ops is a cost advantage Giano structurally cannot reach, and it partly offsets 4337's per-op overhead at scale.
- **Battle-tested validation.** The EntryPoint is among the most scrutinised contracts on Ethereum. A bespoke authorisation path is a bespoke audit — see below.

### 5.5 Design and security observations found while reading

These are properties of the code as written, ordered roughly by how much they'd matter in production. They are relevant to the comparison because most of them are things ERC-4337 (or a mature 4337 account like Coinbase Smart Wallet) has explicit answers for.

1. **No domain separation between ERC-1271 signing and transaction authorisation.** `execute` verifies a WebAuthn signature over `bytes.concat(getChallenge(call))` — a 32-byte value. `isValidSignature(hash, sig)` verifies over `bytes.concat(hash)` — also 32 bytes, through the *same* `_validateSignature`. There is no tag, prefix or EIP-712 wrapper distinguishing the two. So a signature obtained through an ERC-1271 "please sign this hash" flow is, by construction, a valid `execute` authorisation for whatever call hashes to that value — and `getChallenge` is a public view, so an attacker can compute the target hash. Exploitability depends on the signing UI: if it always hashes structured, human-readable typed data the attacker needs a preimage (infeasible), but any integration that signs a counterparty-supplied raw hash (a common ERC-1271 pattern — "sign this order hash") is directly exposed. This is exactly the problem Coinbase Smart Wallet's `replaySafeHash` / ERC-1271 EIP-712 wrapping exists to solve, and it's the finding I'd address first.

2. **No chain ID in the execute challenge.** `getChallenge` commits to `address(this)`, the nonce, and the call — but not `block.chainid`. Because account addresses are deterministic CREATE2 outputs, the same account can exist at the same address on multiple chains, and a signature is then replayable across all of them. In ERC-4337 the `userOpHash` commits to both `chainId` and the EntryPoint address for precisely this reason.

3. **Relayer griefing is unmitigated.** `execute` is permissionless and there is no reimbursement path. A relayer can be made to pay for operations that revert or accomplish nothing. Any production deployment needs off-chain simulation, authentication and rate limiting in front of it — infrastructure that 4337's stake/reputation rules and paymaster accounting handle at the protocol level.

4. **`Account` is not upgradeable.** Direct CREATE2 deployment, immutable `registry`, no proxy, no upgrade hook. A bug in `Account` cannot be patched for existing users, and there is no migration path in the registry — recovery would mean deploying new accounts and moving assets. Most 4337 accounts are proxies specifically to keep that door open.

5. **`fallback() external payable {}` swallows all unmatched calldata** and returns success. A call to a mistyped or non-existent function on an `Account` silently succeeds, which can make an integration believe an operation happened when it did not.

6. **User verification is not enforced on-chain.** Both `_validateSignature` and `_validateAdminSignature` pass `requireUserVerification: false`, so the UV flag in `authenticatorData` is never checked. The demo requests `userVerification: 'required'` at registration, but that is a client-side preference the contract does not enforce — an assertion produced without biometric/PIN still validates. Given that admin operations can add signers and pause the account, requiring UV at least for the `ADMIN` path seems worth considering.

7. **No RP ID or origin check.** The contract never verifies `authenticatorData[0:32] == sha256(rpId)`, nor the `origin` field of `clientDataJSON`. In practice WebAuthn scopes credentials to their RP, so this is mitigated by the browser — but it means the contract trusts browser scoping rather than verifying it itself.

8. **Signature malleability is permitted.** `WebAuthn.verifySignature` calls `P256.verifySignatureAllowMalleability`, never the `verifySignature` variant with the `s <= n/2` check (which exists in `P256.sol` and is unused). For `execute` the nonce makes this harmless. For ERC-1271 there is no nonce, so two distinct valid signatures exist for any signed hash — a hazard for any consumer that dedupes or replay-protects by signature bytes.

9. **`AccountRegistry.createUser` is permissionless, so credential IDs can be squatted.** Nothing proves the caller controls the passkey. An attacker who learns a credential ID can register it against a public key of their own; the credential is then permanently linked (`CredentialAlreadyLinked`) and the legitimate owner can never register it. Griefing rather than theft — the attacker gains no control of the victim's assets — but it is unrecoverable.

10. **`requestAddCredential` on the registry is permissionless too.** Anyone can create a pending credential entry on any registered account. Approval requires an admin signature so it is not an authorisation hole, but it writes attacker-controlled state into the account and, because `_credentialExists` returns true for pending entries, it lets an attacker block the legitimate owner from later requesting that same credential ID.

11. **Minor:** `AccountRegistry.salt` is computed in the constructor from `block.timestamp`/`prevrandao` and never read — dead code. `removeCredential` sets `role = NONE` but leaves `publicKey` and `credentialId` populated. `notifyCredentialRemoved` reads `credentialToAccount[credentialId]` into `account` after establishing it equals `msg.sender`.

---

## 6. Verdict

Giano and ERC-4337 are answers to different questions.

**ERC-4337 asks:** how do we make smart accounts work *everywhere*, with a shared market for relaying and gas sponsorship and a common interface every wallet, SDK and explorer understands? The price is a large shared singleton, a specified but intricate economic layer, per-op gas overhead, and dependence on external infrastructure.

**Giano asks:** what is the smallest thing that gives a user a passkey-controlled, gas-sponsored, multi-device smart account? The answer is refreshingly small — and where it is opinionated, it is opinionated well. The role model, the request→approve device onboarding, and the pause mechanism are a better fit for the actual problem (a consumer wallet with several devices and a recovery story) than anything you get by default in 4337-land, where you'd assemble the same behaviour from ERC-7579/6900 modules.

What Giano trades away is not primarily on-chain: it is the **relayer**. ERC-4337's real product is a specified, competitive, someone-else's-problem market for submitting and sponsoring operations. Giano replaces that with a service you own, with no protocol-level reimbursement or anti-abuse mechanism, represented in this repo by a hardcoded Hardhat key. That is the gap to close before this design carries value on a public chain.

Practically:

- For a **consortium chain, appchain, or any environment you control** — where no bundler exists, you'd run the relayer anyway, and the role/pause semantics are the point — Giano is a genuinely good fit, and simpler and cheaper than 4337.
- For a **public-mainnet consumer wallet**, the ecosystem pull of 4337 is hard to argue against, and the honest comparison is against a mature 4337 passkey account (Coinbase Smart Wallet, Kernel, Safe + passkey module) rather than against the bare standard. Those give you 4337's infrastructure *and* solutions to findings 1, 2 and 4 above.
- Either way, findings **1 (ERC-1271/execute domain separation)** and **2 (missing chain ID)** are worth fixing regardless of which direction the project takes, and are cheap to fix: a domain tag or EIP-712 wrapper around each challenge preimage.

A closing note on the working tree: the untracked residue described in §0 is generated bindings for `GianoSmartWallet`, `MultiOwnable`, a paymaster SDK and a bundler-based stack — which suggests exactly this migration to ERC-4337 exists on another branch. This report describes `main`, which does not contain it.
