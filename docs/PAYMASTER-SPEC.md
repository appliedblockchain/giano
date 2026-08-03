# Giano sponsorship — implementation spec

**The buildable contract for backend-signed gas sponsorship: interfaces, wire formats, schemas and
acceptance criteria.**

Status: spec for implementation · Last updated 2026-07-28 · Owner: Giano team
Rationale, options and trade-offs: [`PAYMASTER-DESIGN.md`](./PAYMASTER-DESIGN.md) — read it first if you
want to know *why*. This document is *what* and *how*, and where the two disagree, this one wins.

> Verified against the tree at time of writing: viem `2.31.6`, `@account-abstraction/contracts@0.7.0`
> (npm — **not** `vendor/account-abstraction`, which is not in the contracts compile path),
> Solidity `0.8.28` via Hardhat, OpenZeppelin `5.3.0`.

---

## Contents

- [1. Scope and invariants](#1-scope-and-invariants)
- [2. The contract](#2-the-contract)
- [3. Wire format](#3-wire-format)
- [4. Backend](#4-backend)
- [5. Client](#5-client)
- [6. Deploy, devnet and registry](#6-deploy-devnet-and-registry)
- [7. Observability and ops](#7-observability-and-ops)
- [8. Test matrix](#8-test-matrix)
- [9. Milestones](#9-milestones)
- [10. Corrections to PAYMASTER-DESIGN.md](#10-corrections-to-paymaster-designmd)

---

## 1. Scope and invariants

A tenant's users get their gas paid when, and only when, the tenant's backend policy says so. On-chain,
that is one ECDSA check against a signature our backend produced. Off-chain, it is a filter and budget
evaluation over the operation.

### 1.1 Five invariants

Each one exists because breaking it produces a failure that is silent until a chain rejects it — or
worse, silently spends money.

| # | Invariant | Mechanical reason |
|---|---|---|
| **I1** | The grant binds **every** field that determines `requiredPreFund` | The EntryPoint computes `requiredPreFund` from the gas fields; leave one unbound and the holder of the grant chooses how much we pay |
| **I2** | The grant is minted **exactly once** per operation | Each mint reserves budget. viem calls the paymaster hooks more than once per prepare unless the client is structured to prevent it ([§5.1](#51-two-blockers-in-the-current-client)) |
| **I3** | **Nothing** mutates a bound field between minting and `signUserOperation` | A mutated field invalidates the paymaster signature (`AA34`) and, after signing, the passkey signature too. Both surface as opaque bundler errors that read like key or hashing bugs |
| **I4** | Validation reads **zero** paymaster storage | ERC-7562 requires an EntryPoint stake for entities that read their own storage during validation. v1 avoids the stake by avoiding the reads ([§1.3](#13-the-cost-of-statelessness)) |
| **I5** | Sponsorship **default-denies** | An empty or absent config sponsors nothing. Note this is the *opposite* of the relay's `allowedTargets: [] == unrestricted` convention (`services/wallet-api/src/services/userop-policy.ts:98`), which is why the two live in separate namespaces |

### 1.2 v1 versus v2

v1 is deliberately the smallest contract that satisfies I1–I5. Everything deferred is deferred behind a
**stable wire format**: v2 adds state without changing the `paymasterAndData` layout, the EIP-712
struct, the endpoint contract or one line of client code.

| | v1 (this spec) | v2 (deferred) |
|---|---|---|
| Signature check | ✅ `immutable verifyingSigner` | signer *set*, rotatable on-chain |
| Validity window | ✅ `validUntil` / `validAfter` | unchanged |
| `tenantId` in the grant | ✅ **bound, unused** | keys the ledger |
| Per-tenant balance ledger | ❌ off-chain only | ✅ `mapping(uint32 => uint256)` |
| Per-tenant daily cap | ❌ | ✅ circuit breaker surviving signer compromise |
| `postOp` | ❌ empty context, `postOpGasLimit = 0` | ✅ debits the ledger |
| `pause()` | ❌ see [§1.3](#13-the-cost-of-statelessness) | ✅ |
| EntryPoint stake | **not required** | **required** |

Binding `tenantId` in v1 costs 4 bytes of calldata and buys a v2 upgrade that is a contract deploy plus
an address change — no re-signing infrastructure, no client release, no endpoint change.

### 1.3 The cost of statelessness

`mapping(address => bool) signers` and `bool paused` are both `SLOAD`s in the validation path, so
either one forfeits I4 and its stake exemption. v1 therefore has neither, and gets its safety
properties elsewhere:

| Want | v1 mechanism |
|---|---|
| Stop sponsoring **now** | Stop signing. The backend is already the gate; this is instant, needs no transaction, and is the fastest kill switch in the system |
| Stop sponsoring **on-chain** | Owner-only `withdrawTo` of the EntryPoint deposit → `AA31` → nothing sponsors. No validation-path storage involved |
| Rotate the signing key | Deploy a new instance; the backend starts returning the new `paymaster` address (the endpoint is authoritative — [§4.2](#42-post-v1paymastersponsor)), so no tenant config changes. Drain the old instance after `validitySeconds`. Grants live ≤5 minutes, so this is a clean cutover runbook, not an outage |
| Per-tenant fund isolation | Not on-chain in v1. A tenant needing it gets its own instance — `allowedPaymasters` is already per-tenant (`services/wallet-api/src/services/tenants.ts:40`), so this composes with no new code |

**State this plainly to anyone reviewing the risk:** in v1 the off-chain budget is the *only* spend
control. A bug in it, or a compromised signer, drains the pooled deposit and every tenant stops being
sponsored. Required compensating controls, none optional:

1. Fund the deposit to a **few days** of expected spend, not months, with automated top-up.
2. Conservative per-tenant and per-user daily budgets from day one.
3. Deposit balance alarm wired to a schedule, not a dashboard ([§7](#7-observability-and-ops)).
4. A staging environment running Alto with `--safe-mode true` before any funded chain — e2e runs
   `--safe-mode false` (`deploy/docker-compose.e2e.yml:28`) and will not catch an ERC-7562 violation.

### 1.4 Out of scope

ERC-20 / token paymasters; user-pays fallback; sponsorship for anything other than EntryPoint v0.7;
the pre-consent sponsorship quote ([§5.7](#57-deferred-the-pre-consent-quote), v1.1); a self-serve
tenant policy admin API (config arrives via `TENANTS_SEED`, as everything else does).

---

## 2. The contract

New file `packages/contracts/src/GianoVerifyingPaymaster.sol`, derived from
`node_modules/@account-abstraction/contracts/samples/VerifyingPaymaster.sol`. Do not import the sample
and subclass it — its `verifyingSigner` handling and non-EIP-712 hash are the parts being replaced.

Conventions, all matching the existing `src/`: `pragma solidity 0.8.28` (pinned, as
`src/GianoSmartWallet.sol`); custom errors at contract scope with natspec, never require-strings
(`src/MultiOwnable.sol:41-79`); Coinbase/Solady natspec house style; no upgradeability.

### 2.1 External surface

```solidity
contract GianoVerifyingPaymaster is BasePaymaster {
    /// @notice The address whose signature authorises sponsorship. Immutable by design:
    ///         reading a signer set would be an SLOAD in validation, which under ERC-7562
    ///         would require this paymaster to be staked (docs/PAYMASTER-SPEC.md §1.3).
    ///         Rotation is a redeploy — the backend returns the paymaster address, so no
    ///         tenant configuration changes.
    address public immutable verifyingSigner;

    error InvalidSignatureLength(uint256 length);
    error InvalidPaymasterDataLength(uint256 length);

    constructor(IEntryPoint _entryPoint, address _verifyingSigner) BasePaymaster(_entryPoint);

    /// @notice The EIP-712 digest the backend signs and this contract verifies.
    ///         Exposed so the signer can cross-check off-chain construction against the
    ///         on-chain definition — see the parity test in §8.1.
    function getHash(PackedUserOperation calldata userOp, uint32 tenantId, uint48 validUntil, uint48 validAfter)
        public view returns (bytes32);

    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public pure returns (uint32 tenantId, uint48 validUntil, uint48 validAfter, bytes calldata signature);

    function domainSeparator() public view returns (bytes32);

    /// @dev MUST remain payable: ignition/modules/Testing.ts funds the paymaster with
    ///      `m.send`, which relies on receive() forwarding to entryPoint.depositTo.
    receive() external payable;
}
```

`withdrawTo` and `deposit` come from `BasePaymaster`; `withdrawTo` is `onlyOwner` and is the on-chain
kill switch. `BasePaymaster`'s constructor calls `_validateEntryPointInterface`, an ERC-165
`supportsInterface` call — so any test must have real EntryPoint code at the address
([§8.1](#81-forge-packagescontractstest)).

### 2.2 Validation

```solidity
function _validatePaymasterUserOp(
    PackedUserOperation calldata userOp,
    bytes32 /* userOpHash */,
    uint256 /* requiredPreFund */
) internal view override returns (bytes memory context, uint256 validationData) {
    (uint32 tenantId, uint48 validUntil, uint48 validAfter, bytes calldata signature) =
        parsePaymasterAndData(userOp.paymasterAndData);

    // Length is checked here rather than in ECDSA so the revert names this contract.
    if (signature.length != 65) revert InvalidSignatureLength(signature.length);

    bytes32 digest = keccak256(
        abi.encodePacked("\x19\x01", domainSeparator(), _hashSponsorship(userOp, tenantId, validUntil, validAfter))
    );

    // A bad signature MUST return SIG_VALIDATION_FAILED, never revert: a revert during
    // validation drops the op from the bundle with an opaque error, while the packed
    // failure flag lets the bundler report AA34 and lets simulation stay useful.
    if (ECDSA.recover(digest, signature) != verifyingSigner) {
        return ("", _packValidationData(true, validUntil, validAfter));
    }

    // Empty context: EntryPoint v0.7 enters postOp only when context.length > 0
    // (EntryPoint.sol:702), so returning "" means postOp is never called and
    // paymasterPostOpGasLimit can be 0 — which lowers requiredPreFund for every op.
    return ("", _packValidationData(false, validUntil, validAfter));
}
```

Every read in that function is an immutable or calldata. `verifyingSigner` and `entryPoint` are
immutables (in code, not storage); `ECDSA.recover` and `_packValidationData` are pure. `BasePaymaster`
inherits OpenZeppelin `Ownable`, whose `owner()` **is** storage — but it is only read by `onlyOwner`
admin functions, never in validation. I4 holds.

There is no `_postOp` override. `BasePaymaster.postOp` remains inherited and unreachable, because the
EntryPoint never calls it with an empty context. Do not add one in v1: a reverting `postOp` reverts the
user's call while the paymaster is still charged (`EntryPoint.sol:705-712`, `PostOpReverted`).

### 2.3 The EIP-712 domain

Recompute from string literals on each call, following the in-repo precedent
`packages/contracts/src/ERC1271.sol:101-113`, **not** OpenZeppelin `EIP712`:

```solidity
function domainSeparator() public view returns (bytes32) {
    return keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Giano Sponsorship"),
            keccak256("1"),
            block.chainid,
            address(this)
        )
    );
}
```

Recomputing is ~100 gas of `keccak256` over constants. OpenZeppelin's `EIP712` caches the separator in
immutables but falls back to **storage-held name/version strings** when `block.chainid` changes, which
would be a conditional `SLOAD` in the validation path — exactly what I4 forbids. Recomputation is both
cheaper than a cold `SLOAD` (2100 gas) and unconditionally storage-free.

`address(this)` in the domain means a grant for one deployed instance is structurally unusable against
another, which is what makes the [§1.3](#13-the-cost-of-statelessness) rotation runbook safe.

### 2.4 The signed struct

Final. Field order is normative — it must match the backend's `encodeAbiParameters` call exactly, and
the parity test in [§8.1](#81-forge-packagescontractstest) exists to prove it does.

```
Sponsorship(
  address sender,
  uint256 nonce,
  bytes32 initCodeHash,
  bytes32 callDataHash,
  bytes32 accountGasLimits,
  uint256 paymasterGasLimits,
  uint256 preVerificationGas,
  bytes32 gasFees,
  uint32  tenantId,
  uint48  validUntil,
  uint48  validAfter
)
```

| Field | On-chain source | Covers |
|---|---|---|
| `sender` | `userOp.getSender()` | which account is sponsored |
| `nonce` | `userOp.nonce` | makes the grant single-use — the EntryPoint's nonce is the replay protection, so no separate grant nonce is needed |
| `initCodeHash` | `keccak256(userOp.initCode)` | the ~200k deployment of a first-time user |
| `callDataHash` | `keccak256(userOp.callData)` | the transaction the filters matched |
| `accountGasLimits` | `userOp.accountGasLimits` | packed `verificationGasLimit ‖ callGasLimit` |
| `paymasterGasLimits` | `uint256(bytes32(userOp.paymasterAndData[20:52]))` | packed `paymasterVerificationGasLimit ‖ paymasterPostOpGasLimit` — the 32-byte slice covers **both**, per `UserOperationLib.sol:14-16` |
| `preVerificationGas` | `userOp.preVerificationGas` | L1 calldata cost |
| `gasFees` | `userOp.gasFees` | packed `maxPriorityFeePerGas ‖ maxFeePerGas` — **the field most often left unbound, and the one that lets a holder name our price** |
| `tenantId` | our grant | bound in v1, keys the v2 ledger |
| `validUntil` | our grant | how long an unspent grant lingers |
| `validAfter` | our grant | normally `0`; present so the struct matches the wire layout |

Everything except the signature is bound; `chainId` and the paymaster address are bound by the domain.
That is the whole of I1, and the failure mode to guard against is a future "simplification" of this
list.

**`requiredPreFund` needs no separate signed cap.** The EntryPoint derives it purely from
`accountGasLimits`, `paymasterGasLimits`, `preVerificationGas` and `gasFees` — all bound above — so an
explicit `maxCost` would be redundant calldata restating a number the grant already fixes.

---

## 3. Wire format

`paymasterAndData`, with the first 52 bytes fixed by EntryPoint v0.7
(`UserOperationLib.sol:14-16`):

| Bytes | Width | Field |
|---|---|---|
| `[0:20]` | 20 | paymaster address |
| `[20:36]` | 16 | `paymasterVerificationGasLimit` (`uint128`) |
| `[36:52]` | 16 | `paymasterPostOpGasLimit` (`uint128`) — **0 in v1** |
| `[52:56]` | 4 | `tenantId` (`uint32`) |
| `[56:62]` | 6 | `validUntil` (`uint48`, unix seconds) |
| `[62:68]` | 6 | `validAfter` (`uint48`, unix seconds) |
| `[68:133]` | 65 | signature (`r ‖ s ‖ v`) |

**81 bytes of `paymasterData`.** The upstream sample uses 129 by `abi.encode`-ing two `uint48`s into 64
bytes; packing matters because `paymasterData` is calldata, at ~16 gas per non-zero byte on L1 and a
dominant term in `preVerificationGas` on rollups.

`parsePaymasterAndData` must reject any `paymasterAndData` whose length is not exactly 133
(`InvalidPaymasterDataLength`) — a short slice would otherwise read out of bounds or silently
misinterpret fields.

### 3.1 `initCode` reconstruction — read this before implementing the backend

The contract hashes `userOp.initCode`, a single `bytes` field. viem's v0.7 user operation has no
`initCode`: it carries `factory` and `factoryData` separately. The backend must reconstruct:

```ts
const initCode = factory ? concat([factory, factoryData ?? '0x']) : '0x'
```

Get this wrong and **only the first operation of every new user fails** — the one carrying deployment.
Everything else works, so it survives a happy-path test and breaks every real signup. There is an
explicit test for it in [§8.3](#83-vitest-serviceswallet-api).

### 3.2 Validity window

`validitySeconds` is per-tenant, default **180**, allowed range **120–300**.

The EntryPoint checks `validUntil` at *execution* time, not submission, so the window must absorb
clock skew, the passkey ceremony, the relay round trip and bundler mempool latency. Too long and unspent
grants accumulate against optimistic budget reservations.

One consequence to put in the wallet UI copy: because `maxFeePerGas` is bound, a base-fee spike above
the signed value means the operation is simply not included and expires. That is correct behaviour —
the user retries and gets a fresh grant at the new price — but silence looks like a hang.

---

## 4. Backend

All in `services/wallet-api`.

### 4.1 The signer

```ts
// src/services/sponsor-signer.ts
export interface SponsorSigner {
  /** The address the paymaster's immutable verifyingSigner must equal. */
  readonly address: Address;
  /** Signs a 32-byte EIP-712 digest, returning 65-byte r‖s‖v. */
  signDigest(digest: Hex): Promise<Hex>;
}
```

Two implementations, selected by env:

| `SPONSOR_SIGNER` | Implementation | Use |
|---|---|---|
| `local` | `privateKeyToAccount(SPONSOR_PRIVATE_KEY).sign({ hash })` | dev, e2e, CI — no AWS dependency |
| `kms` | AWS KMS `Sign` on an `ECC_SECG_P256K1` `SIGN_VERIFY` key (`SPONSOR_KMS_KEY_ID`) | production |

New env vars go in the `envSchema` zod object at `services/wallet-api/src/config.ts:20`, following its
existing patterns (`z.enum` with a default, `addressSchema` for addresses). Extend the existing
`.superRefine` (`services/wallet-api/src/config.ts:93-109`) so that `kms` requires `SPONSOR_KMS_KEY_ID` and `local` requires
`SPONSOR_PRIVATE_KEY` — a misconfiguration must fail at boot, not at the first sponsored transaction.
Add `SPONSOR_PAYMASTER_ADDRESS` and validate at boot that it matches `verifyingSigner` on-chain
([§7](#7-observability-and-ops)).

**The KMS adapter is the one fiddly piece.** KMS returns a DER-encoded `(r, s)` with no recovery id,
and `s` is in the upper half of the curve order about half the time. The adapter must:

1. DER-decode to `(r, s)`.
2. Normalise: if `s > n/2`, set `s = n - s`.
3. Recover `v` by trying `27` and `28` and keeping the one that recovers to `signer.address`.

Unit-test it against a known KMS response fixture and against `privateKeyToAccount` parity for the same
digest. It is twenty lines and a surprising afternoon if unexpected.

**This breaks a stated invariant.** `ARCHITECTURE.md` describes `wallet-api` as *"holds no private
key"*, and that line is load-bearing in how the system has been reviewed. Update it in M5 rather than
letting the docs and the code diverge.

### 4.2 `POST /v1/paymaster/sponsor`

New `src/routes/paymaster.ts`, a plain async route plugin taking
`{ db, config, signer, defaultPolicy }`, registered in `src/app.ts` after `useropRoutes`
(`src/app.ts:100-113`).

```ts
preHandler: [app.requireSession, sponsorLimit]
```

Tenant resolution is inherited wholesale from the relay: the `onRequest` hook in `plugins/tenant.ts`
resolves `Origin` → `getByOrigin`, and `requireSession` cross-checks it against `session.tenantId`
(`plugins/auth.ts:66-70`), incrementing the alertable `giano_cross_tenant_rejections_total`. Nothing
new needs writing, and the BYO edge requirement to forward `Origin` untouched
(`e2e/wallet-byo/serve.mjs:49-74`) already covers this path.

`sponsorLimit` mirrors the relay's per-tenant fixed window (`src/routes/userops.ts:87-103`) with its own
`sponsorRateLimitPerMinute` override. Note the same caveat applies — in-memory, single-process — which
is fine for a rate limit and **not** fine for budgets ([§4.4](#44-budget-accounting)).

**Request**

```ts
z.object({
  mode: z.enum(['estimate', 'final']),
  chainId: z.number().int().positive(),
  entryPoint: address,
  userOperation: z.object({
    sender: address,
    nonce: hexQuantity,
    callData: hexData,
    factory: address.optional(),
    factoryData: hexData.optional(),
    callGasLimit: hexQuantity,
    verificationGasLimit: hexQuantity,
    preVerificationGas: hexQuantity,
    maxFeePerGas: hexQuantity,
    maxPriorityFeePerGas: hexQuantity,
  }).strip(),
})
```

`.strip()` per the relay's convention (`src/routes/userops.ts:43`) — and for the same reason: the
server's `chainId` and EntryPoint are authoritative, so a client-supplied value is dropped rather than
trusted. Reject any `chainId`/`entryPoint` mismatch with the server's config as `400`.

**Response `200`**

```ts
z.object({
  paymaster: address,
  paymasterData: hexData,
  paymasterVerificationGasLimit: hexQuantity,
  paymasterPostOpGasLimit: hexQuantity,   // "0x0" in v1
  sponsor: z.object({ name: z.string(), icon: z.string().optional() }).optional(),
  validUntil: z.number().int(),
})
```

Deliberately the shape of ERC-7677 `pm_getPaymasterStubData` / `pm_getPaymasterData`, so that pointing
a tenant at a third-party sponsorship provider later is a config change rather than a rewrite.

**Error `403`** — `{ error: 'sponsorship-denied', message, reason, policy: PolicyRuleResult[] }`,
reusing the relay's rejection body shape (`src/routes/userops.ts:115`) and the canonical
`{ error, message }` envelope from `plugins/error-handler.ts:19-42`.

**Five requirements on this endpoint**

1. **`estimate` and `final` must return identical `paymasterData` length** (133-byte
   `paymasterAndData`, always). `estimate` returns a throwaway 65-byte signature, needs no key, and
   debits no budget. Its only job is to make `preVerificationGas` estimation correct.
2. **`estimate` and `final` must return the same paymaster gas limits**, and `final`'s values are the
   ones the grant is signed over. The client merges them verbatim and never re-estimates them.
3. **Sender binding**: reject unless `userOperation.sender == session.walletAddress` — the same check
   as `userop-policy.ts:67`. Without it, a user of tenant A obtains sponsorship for any account.
4. **The endpoint owns the paymaster address.** It returns `config.SPONSOR_PAYMASTER_ADDRESS`, so the
   signer and the contract can never disagree, and rotation needs no tenant config change.
5. **`paymasterVerificationGasLimit`** must cover `ECDSA.recover` plus the domain keccak — budget
   ~50,000 and measure in M1. Under-setting it produces an `AA33` that reads as a policy bug.

### 4.3 The policy engine

New `src/services/sponsorship-policy.ts`. **Do not add rules to `evaluatePolicy`** — the relay's rule
list is asserted to be exactly 7 entries by `test/userop-policy.test.ts:58`, and the two gates answer
different questions ([§4.3.2](#432-relationship-to-the-relay-gate)).

Reuse `decodeCallTargets` (`src/services/userop-policy.ts:46`) and emit the same
`PolicyRuleResult[]`, so a sponsorship decision is auditable the same way a relay decision is. One
behavioural difference to implement deliberately: `decodeCallTargets` returns `null` for an
undecodable selector, which the relay maps to *fail the allowlist rule*; sponsorship maps it to
**deny outright**.

#### 4.3.1 Configuration

Lives under the existing `tenants.policy` jsonb as a new `sponsorship` sub-schema on
`tenantPolicySchema` (`src/services/tenants.ts:33`). That schema is `.strict()` and
`test/tenants.test.ts:49-52` asserts the strictness — so the field **must** be added there or every
seed carrying it is rejected at boot.

```jsonc
{
  "sponsorship": {
    "enabled": true,
    "tenantId": 7,                        // the uint32 in the grant. IMMUTABLE — see §4.3.3
    "validitySeconds": 180,
    "maxFeePerGas": "30000000000",        // sign-time ceiling, tighter than the relay cap
    "maxCallGas": "300000",
    "maxCallsPerBatch": 4,
    "sponsorDeployment": true,            // the +200k first-op initCode, separately switchable
    "budgets": {
      "perOpWei":           "5000000000000000",
      "perUserPerDayWei":  "20000000000000000",
      "perUserPerMonthWei":"200000000000000000",
      "perTenantPerDayWei":"5000000000000000000"
    },
    "default": "deny",                    // ← only "deny" is accepted in v1
    "rules": [
      {
        "id": "usdc-transfer",
        "effect": "allow",
        "targets":   ["0xa0b8...eb48"],
        "selectors": ["0xa9059cbb"],
        "argConstraints": [{ "index": 1, "type": "uint256", "op": "lte", "value": "1000000000" }],
        "budgets": { "perUserPerDayWei": "5000000000000000" }
      },
      { "id": "nft-mint-launch", "effect": "allow", "targets": ["0x1234...cdef"],
        "selectors": ["0x1249c58b"], "notAfter": "2026-08-15T00:00:00Z" }
    ]
  }
}
```

Evaluation semantics, all chosen so mistakes fail closed:

1. Absent `sponsorship`, or `enabled: false` → sponsor nothing. **Absence is denial.**
2. Every call in the operation must match ≥1 `allow` rule and no `deny` rule. An `executeBatch` with
   one unmatched call is denied **wholesale**, never partially.
3. Rules evaluate in order; the first matching rule's own budgets apply *in addition to* the
   tenant-level budgets, never instead of them.
4. `default` accepts only `"deny"` in v1. The field exists so the intent is explicit in every tenant's
   config rather than implied by the code.
5. Bigints are decimal strings at rest, per the existing convention (`services/tenants.ts:26`).

Seed-time validation (in `tenantPolicySchema`'s `superRefine`) must reject: `enabled: true` with an
empty `rules` array; a missing or duplicate `tenantId`; `validitySeconds` outside 120–300; `default`
anything but `"deny"`.

#### 4.3.2 Relationship to the relay gate

Both gates stay. They are not redundant.

| | Sponsor gate (before signing) | Relay gate (after signing) |
|---|---|---|
| Question | "will we pay for this?" | "will we forward this?" |
| Default | **deny** | allow, with caps |
| Scope | globally binding — the contract enforces it | our submission path only |
| Still needed because | — | self-paid ops, and ops whose grants were minted earlier |

The requirement is that they share one rule library. Two divergent policy engines in one service is
precisely the maintenance failure this design exists to avoid.

#### 4.3.3 `tenantId` is immutable

Once grants have been issued under `tenantId: 7`, that number is as immutable as `rp_id` already is.
In v2 it keys a balance; reassigning it hands one tenant's money to another. Enforce it the way
`walletOrigin` and `rpId` are enforced today — uniqueness across seeds in `tenantsSeedSchema`
(`services/tenants.ts:107-120`) and an immutability guard in `seedTenants` with the same error style
as the `rp_id` guard (`services/tenants.ts:157-163`).

#### 4.3.4 The limit of target/selector filtering

A whitelisted target that can make arbitrary sub-calls — a router, a multicall, Permit2, a proxy under
someone else's control — voids the filter. `(target, selector)` establishes that the user called
`transfer` on a contract; it says nothing about what that contract then did with our gas. Whitelisting
a router is equivalent to whitelisting everything it can reach.

This is not fixable by a better matcher. It is a **tenant onboarding review item**: for each allowed
target, who controls it and what can it call? `argConstraints` help for known ABIs and are the right
tool for value ceilings, but they do not close this.

### 4.4 Budget accounting

In v1 this is the *only* spend control, so it gets the most rigour in the spec.

Sponsorship authorises a maximum and learns the actual cost blocks later, so four states:

```
reserve  →  at sign time, debit requiredPreFund from the tenant's and user's budgets
consume  →  at relay time, bind the reservation to the userOpHash
settle   →  on receipt, replace the reservation with actualGasCost
expire   →  a sweep releases reservations past validUntil that were never consumed
```

**`settle` is mandatory, not an optimisation.** WebAuthn forces `verificationGasLimit ≥ 800_000`
(`packages/wallet-core/src/account/toGianoSmartAccount.ts:264-273`) against ~205k actual consumption
(`COST-MODEL.md` §5.2) — roughly a **4× over-reservation**. Without settlement, users hit their daily
budget at a quarter of the intended spend.

**Settlement is receipt-driven, not relay-driven.** `consume` is unreachable on the embedded / BYO path
where `injection.submitUserOperation` is undefined and the operation never passes through
`POST /v1/userops` ([§5.2](#52-the-corrected-order)). So:

- Settle **opportunistically** in the already-public `GET /v1/userops/:hash/receipt` handler
  (`src/routes/userops.ts:272-285`) — every dApp polls it, so this is nearly free.
- Plus a **sweeper** for expiry and for operations nobody polled.

#### Schema

`migrations/0003_sponsorship.sql`, hand-written, plus a hand-mirrored table in `src/db/schema.ts`.
There is no drizzle-kit in this repo — `schema.ts` is a maintained mirror of the SQL and the
constraint names must agree between them (see the note in `migrations/0002_tenants.sql`).

```sql
CREATE TABLE sponsorship (
  userop_hash  text PRIMARY KEY,                          -- same key as userop_log; joins for free
  tenant_id    uuid NOT NULL REFERENCES tenants(id),
  user_id      uuid REFERENCES users(id) ON DELETE SET NULL,
  sender       text NOT NULL,
  nonce        numeric NOT NULL,
  request_hash text NOT NULL,                             -- keccak of the bound fields: idempotency
  reserved_wei numeric NOT NULL,
  actual_wei   numeric,                                   -- null until settled
  status       text NOT NULL,                             -- issued|consumed|settled|expired|denied
  rule_id      text,                                      -- which allow rule matched
  valid_until  timestamptz NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX sponsorship_request_hash_key ON sponsorship (request_hash);
CREATE INDEX sponsorship_budget_idx ON sponsorship (tenant_id, user_id, created_at)
  WHERE status <> 'expired';
```

Follow the schema conventions in `src/db/schema.ts`: explicit snake_case column names, the array form
`(t) => [...]` for constraints, `text('status', { enum: [...] })` rather than a `pgEnum` with the CHECK
constraint in SQL.

#### Concurrency

The budget check and the reservation insert happen in **one `SERIALIZABLE` transaction**, or two
concurrent requests both pass a check that neither should. `sponsorship_request_hash_key` is the
server-side idempotency backstop from [§5.5](#55-minting-exactly-once): a repeat request for an
identical operation within the window returns the *same* grant and creates no second reservation.

Two useful by-products: per-tenant gas billing becomes a `GROUP BY` rather than a chain-log
reconstruction, and `rule_id` answers the question every tenant will ask — *which* of my rules is
eating my budget?

### 4.5 Generated artefacts

`pnpm openapi` must be re-run and `openapi/openapi.json` committed; `openapi:check` is a CI drift gate
(`openapi/generate.ts:32-40`). The `security` key on the new route must be `[{ session: [] }]` to match
the schemes declared at `src/app.ts:80-83`.

---

## 5. Client

viem is pinned at `2.31.6` across every workspace member. Line references below are to
`node_modules/.pnpm/viem@2.31.6_*/node_modules/viem/account-abstraction/actions/bundler/prepareUserOperation.ts`.

### 5.1 Two blockers in the current client

Neither is optional to fix, and neither is visible without reading viem's internals.

**Blocker 1 — the hooks fire four times, twice against an empty operation.**
`packages/wallet-core/src/provider.ts:208` calls `bundler.estimateUserOperationGas`, which internally
runs its own `prepareUserOperation` with `parameters: ['authorization','factory','nonce','paymaster','signature']`
(`estimateUserOperationGas.ts:170-185`) — note the absence of `'gas'` and `'fees'`. So both paymaster
hooks fire against an operation whose gas and fee fields are `undefined`, minting a grant that binds
nothing. Then `provider.ts:213` calls `prepareUserOperation` properly, firing both again.

Deleting the redundant `estimateUserOperationGas` removes exactly the two pathological fires. viem's
*internal* estimate at `:622` does **not** re-fire the hooks, because `request.paymaster` is by then
an address string and both hook guards test `!paymasterAddress`.

**Blocker 2 — fees are overwritten after the last hook.** `provider.ts:218-221` spreads
`resolveUserOpFees(...)` over the prepared operation, after `getPaymasterData` has already returned.
The grant covers one `maxFeePerGas`; the submitted operation carries another. Every transaction fails
`AA34`, and it looks like a signer or hashing bug.

> **Verified: fixing this is behaviour-preserving.** `resolveUserOpFees` prefers
> `prepared.maxFeePerGas`, which viem fills with a deliberate 2× buffer (`:474-483`) — but only if it
> can estimate fees, and it estimates against `bundlerClient.client ?? client`, which resolves to the
> bundler client itself (`:332`) when `createBundlerClient` is given no `client` — as at
> `services/wallet-web/src/wallet.ts:50`. Probed against the running e2e stack, Alto rejects
> `eth_feeHistory`, `eth_maxPriorityFeePerGas` and `eth_gasPrice` outright ("Invalid discriminator
> value" — it accepts only the ERC-4337 method set plus `eth_chainId`). So viem's fee fill always
> throws, the `catch` at `:485` returns `undefined`, and the third tier — wallet-web's own
> unbuffered `estimateFeesPerGas` (`wallet.ts:69-78`) — is already authoritative. Pre-resolving fees
> produces the identical value; it just makes the unreachable tier unreachable *by construction*
> instead of by accident. **viem's 2× buffer is not in play today and must not be introduced as part
> of this change** — that would be a live behaviour change wearing a refactor's clothing.

There is also a third, pre-existing bug this change should fix: `eth_sendSignedUserOperation`
(`provider.ts:556-566`) feeds an already-signed operation back into the prepare-and-sign path, so it
re-prepares and re-signs — a second passkey prompt today, and a second minted grant after this work.

### 5.2 The corrected order

```
resolve fees                        ← ours, before anything the grant binds
  ↓
prepareUserOperation (exactly one)
  ├─ fees already supplied → :439-443 returns the request unchanged, pinning them
  ├─ getPaymasterStubData        :563   ← shape only, no key, no budget
  ├─ account estimateGas hook    :601   ← the 800k verificationGasLimit floor
  ├─ eth_estimateUserOperationGas :622  ← does NOT re-fire the hooks
  └─ getPaymasterData            :664   ← THE ONLY MINT
  ↓
assert the grant still covers the operation
  ↓
signUserOperation                   ← paymaster fields are already inside the hash
  ↓
submit, mutating nothing
```

Note this order differs from `PAYMASTER-DESIGN.md` §5's diagram, which shows fees being resolved
*after* gas estimation. viem fills fees at `:435-488`, inside the `Promise.all` that completes before
the stub hook — so "resolve fees first" is not a stylistic preference, it is the only position that
works.

**`isFinal` must be returned as `false`, explicitly, with a comment.** It is read only from the stub
response (`:579`), and the stub hook runs before gas is filled — so `isFinal: true` would commit a
grant binding `undefined` gas limits. The only world where it is correct is one where the client
computes every gas limit itself, which reintroduces the double prepare being removed.

**The embedded branch still sponsors.** When `injection.submitUserOperation` is undefined, prepare,
assert and sign identically; only the final submission differs. Refusing to sponsor embedded flows
would silently break `e2e/wallet-byo` and any embedder. The accounting consequence is handled in
[§4.4](#44-budget-accounting).

### 5.3 Where the sponsorship fetch lives

**A new optional method on `GianoProviderInjection`** (`packages/wallet-core/src/provider-injection/injection.ts`):

```ts
getSponsorship?: (request: SponsorshipRequest) => Promise<SponsorshipGrant>;
```

Not the `paymaster` object in `wallet.ts` that `PAYMASTER-DESIGN.md` §4.3 describes. Three reasons:

1. The endpoint is session-authenticated, and the token is private to
   `create-wallet-api-injection.ts:59` — reachable only through `getSessionToken()`. Wiring it in
   `wallet.ts` means reimplementing that module's `api()` wrapper and its error mapping.
2. A bundler-client-level `paymaster` cannot pre-resolve fees, dedupe the mint, or assert the
   invariant — all three live *around* `prepareUserOperation`, which is wallet-core's concern.
3. That block is a **verbatim clone** in `e2e/wallet-byo/src/runtime.ts:46-58`. Anything added there
   is added twice.

#### The three-file rule

`_with-validation/with-validation.ts:33` iterates `Object.keys(validationHooks)` — **not** the
implementation's keys. A method with no entry in `_with-validation/validation-hooks.ts` is never copied
onto the wrapper, so `injection.getSponsorship` would be `undefined` inside `provider.ts` and **every
operation would silently go unsponsored**. Three files change together:

| File | Change |
|---|---|
| `provider-injection/injection.ts` | the optional method on the type, and a clause in `isGianoProviderInjection` (`:56-74`) |
| `_with-validation/validation-hooks.ts` | a hook validating the grant shape (address, hex, bigint limits) — reuse `assertHex` / `assertHexAddress` from `../types` |
| `wallet-api/create-wallet-api-injection.ts` | the implementation, using the existing `api()` wrapper with `auth: true` |

Guarded by test case 12 in [§8.2](#82-vitest-packageswallet-core).

#### Both SPAs shrink

`services/wallet-web/src/wallet.ts:53-62` and `e2e/wallet-byo/src/runtime.ts:49-57` are **deleted** —
sponsorship arrives with the injection. To stop the remaining duplication drifting, extract into
wallet-core:

- `createPermissivePaymaster(address)` — the devnet paymaster block, clearly labelled devnet-only.
- `createChainFeeEstimator(publicClient)` — the fee estimator both files currently clone. Unbuffered,
  matching today's effective behaviour per the note in [§5.1](#51-two-blockers-in-the-current-client).

Then each SPA is two imports rather than 25 duplicated lines.

#### Serialization

Do **not** reuse `serializeUserOperation` (`wallet-api/serialization.ts:66-103`) for the request body:
it emits the paymaster gas limits only when `op.paymaster` is set, which is true in `final` mode (the
stub set it) and false in `estimate`. Write a dedicated `serializeSponsorshipRequest` that emits the
bound-field set explicitly with `signature` omitted, mirroring the endpoint's zod schema.

### 5.4 The invariant assertion

One canonical projection of the bound fields, shared by the mint-once memo, the assertion and the
tests. Compared: the eight fields from [§2.4](#24-the-signed-struct), plus `factory` and `factoryData`
(the `initCode` preimage), plus the four paymaster fields the grant itself supplied — fourteen string
comparisons. Not compared: `signature` (not bound), `chainId` and `entryPoint` (bound by the domain
and fixed for the client).

Two rules that make it useful rather than decorative:

- **`undefined` canonicalises to its own sentinel**, never to `0` or `'0x'`. A missing bound field is
  a bug, and it must read as one.
- **The error names the offending field**, so an ordering regression surfaces as
  `maxFeePerGas 0x3b9aca00 → 0x2540be400` rather than `AA34`.

It runs immediately before `signUserOperation`, and again — cheaply — on the object handed to the
relay. `signUserOperation` needs no change: `toGianoSmartAccount.ts:241-262` hashes the whole
operation via viem's `getUserOperationHash`, so the paymaster fields are already inside the
passkey-signed digest.

One extra check belongs here: **assert `prepared.sender === await account.getAddress()`** rather than
overwriting it as `provider.ts:229` does today. `signUserOperation` *substitutes* the account address
into the hashed operation (`toGianoSmartAccount.ts:249-252`), so a divergence would have the passkey
signing a different sender than the one sponsored.

### 5.5 Minting exactly once

| Mechanism | Role |
|---|---|
| **Restructure to a single prepare** ([§5.2](#52-the-corrected-order)) | **Primary.** Removes the cause, not the symptom, and is directly testable by counting hook calls |
| Per-attempt memo keyed on the bound-field projection | Defence in depth. Same operation → reuse; *different* operation within one attempt → throw, because that is an ordering regression |
| `sponsorship_request_hash_key` on the endpoint ([§4.4](#44-budget-accounting)) | Backstop. The only mechanism that survives a client bug, a page reload, or a user hammering Approve |

The memo lives in a per-attempt session object created inside the submit path, so it can never leak
across transactions.

Also assert that `final`'s `paymasterData` is no longer than the stub's — a longer one means
`preVerificationGas` was estimated too low and the bundler will reject the operation for reasons that
point nowhere near the cause.

### 5.6 Errors

```
GianoSponsorshipError                    (extends GianoError)
├── GianoSponsorshipDeniedError          403 — policy said no; carries reason + PolicyRuleResult[]
├── GianoSponsorshipUnavailableError     5xx / network / KMS — retryable
├── GianoSponsorshipMismatchError        §5.4 — our bug, never the user's
└── GianoSponsorshipReentryError         §5.5 — our bug
```

`GianoError` (`packages/wallet-core/src/giano-error.ts:36-61`) already fixes the prototype chain and
`name`, and `withValidation` rethrows without wrapping, so the classes survive the seam. Distinguishing
denied from unavailable is what lets the UI say "not allowed" versus "try again".

The `api()` wrapper (`create-wallet-api-injection.ts:66-87`) currently flattens every HTTP failure to
`Error('wallet-api ${path} failed: ${message}')`, discarding the status. Keep that message format
byte-identical — `toRpcError`'s `/not connected/i` heuristic depends on message shapes — but throw a
typed error carrying `status` and the parsed body.

Two new codes in `packages/wallet-transport/src/protocol.ts`'s `RPC_ERRORS`:

| Code | Name | Why not an existing one |
|---|---|---|
| `-32010` | `SPONSORSHIP_DENIED` | `4001` would tell the dApp the *user* declined; `-32603 INTERNAL` hides a policy outcome in a bug bucket |
| `-32011` | `SPONSORSHIP_UNAVAILABLE` | distinguishes retryable from refused |

EIP-1474 reserves `-32000..-32099` for server-defined errors, which is exactly what these are. Two
branches in `toRpcError` (`services/wallet-web/src/requests.ts:62-75`) map the classes to the codes,
passing `policy` through as `data`. `TransportHost.onRequest` already funnels everything through
`toRpcError` (`host.ts:48-52`), so nothing else changes.

**`packages/connector` needs no change** and stays entirely paymaster-unaware. It rethrows
`TransportRpcError` untouched (`thin/create-giano-wallet-provider.ts:125-132`) and already re-exports
`RPC_ERRORS`, so a dApp can test `error.code === RPC_ERRORS.SPONSORSHIP_DENIED` as soon as the constant
lands.

### 5.7 Deferred: the pre-consent quote

`PAYMASTER-DESIGN.md` §4.3 suggests showing "gas sponsored by X" before the user approves. **Not in
v1.** Ship it once `giano_sponsorship_denied_total` shows whether post-approval denials actually happen.

The reasoning: a truthful quote needs the gas fields, so it needs a full `prepareUserOperation` before
the consent screen — the most latency-sensitive moment in the flow. A cheap quote from `calls` alone
avoids the round trip but creates a **third policy mode that can legitimately disagree with `final`**,
and "gas paid by Acme" followed by a denial is strictly worse than an honest error. Spend the v1 effort
on [§5.6](#56-errors) instead.

When it is built: `PendingRequest` (`services/wallet-web/src/requests.ts:4-11`) gains an advisory
`context` field, `host.ts` fetches the quote between resolving the dApp origin and calling
`requestConsent`, and `ReviewTransaction.tsx` gets one more `.kv` row after Value (`:37-40`). The quote
mode must be read-only server-side — no signature, no reservation, no row — and the client must discard
its output entirely rather than feeding it into the operation.

---

## 6. Deploy, devnet and registry

### 6.1 Exporting a new contract — four touch points

`scripts/generate-addresses.ts` is generated-from-generated, so missing a step produces a CI drift
failure rather than a runtime one:

1. An Ignition module entry, so the future id lands in `deployed_addresses.json`.
2. The `Module#Contract` → field mapping in `FUTURE_TO_FIELD` (`scripts/generate-addresses.ts:16-21`).
3. The field in **both** `fieldOrder` (`:71`) and the `GianoDeployment` type inside that script's
   template literal (`:91-102`).
4. Commit the regenerated `addresses.ts` **and** `generated.ts` — wagmi produces
   `gianoVerifyingPaymasterAbi` automatically from the Hardhat artifact, no config change needed. CI
   gates both (`addresses.ts drift check`, `generated-drift`).

Field name: `verifyingPaymaster`, keeping the existing `paymaster` field meaning "the testing
permissive paymaster" so no existing consumer changes meaning underneath.

Build settings are load-bearing for CREATE2: Hardhat, solc `0.8.28`, optimizer runs 200, viaIR, salt
`0xAB00…00AB` (`hardhat.config.ts:17-82`). Foundry builds unoptimised and is for tests only —
deploying with forge would produce a different address.

### 6.2 Devnet

A new Ignition module deploying `GianoVerifyingPaymaster` with the local dev signer's address, funded
via `m.send` → `receive()` → `entryPoint.depositTo`, exactly as `ignition/modules/Testing.ts` funds the
permissive one. Keep `PAYMASTER_FUND_ETH` as the override.

`e2e/devnet/state.json` must be regenerated. **There is no committed script for this** — the state is a
manual `anvil_dumpState` and the nearest executable recipe is `.github/workflows/determinism.yml`.
Write that script as part of M1; the absence of it is a latent problem this work should not inherit.

`deploy/docker-compose.e2e.yml` changes: `TENANTS_SEED` (`:69-91`) gains a `policy.sponsorship` block
per tenant with distinct `tenantId`s and deliberately different rules, so the isolation tests have
something to bite on; `wallet-api` gains `SPONSOR_SIGNER=local` plus the anvil key and the paymaster
address; `wallet-web`'s `GIANO_PAYMASTER_ADDRESS` (`:114`) is **removed** so the sponsored path is the
only path under test.

### 6.3 `config.json` transition

`services/wallet-web/src/config.ts:11,40` keeps `paymasterAddress`, falling back to
`gianoAddresses[chainId].paymaster`. It stays for devnet and embedded use, but wallet-core's per-call
paymaster wins over a bundler-client-level one (`prepareUserOperation.ts:338`) — so a tenant with both
configured has a dead-but-plausible-looking config value. Emit a warning at
`createGianoProvider` time when both are present.

---

## 7. Observability and ops

New metrics, added to **both** the `declare module` block and the object literal in
`src/plugins/metrics.ts:7-18`, every one carrying the `tenant` label (slug — human-readable, bounded
cardinality) per the convention at `:22-24`:

| Metric | Type | Labels |
|---|---|---|
| `giano_sponsorship_issued_total` | Counter | `tenant`, `rule` |
| `giano_sponsorship_denied_total` | Counter | `tenant`, `reason` |
| `giano_sponsorship_reserved_wei` | Counter | `tenant` |
| `giano_sponsorship_settled_wei` | Counter | `tenant` |
| `giano_sponsor_sign_seconds` | Histogram | `signer` (`local`/`kms`) |
| `giano_paymaster_deposit_wei` | Gauge | — |

The gap between `reserved` and `settled` is the reconciliation lag; a persistent gap means the settle
path is broken and budgets are silently over-counting.

**`scripts/doctor.ts` additions.** Today it checks only that the paymaster has code and that
`IEntryPoint.balanceOf(paymaster) ≥ 0.02 ETH`, warn-only (`doctor.ts:188-207`). Add:

- `verifyingSigner()` on-chain equals the configured signer's address — the single most likely
  misconfiguration, and currently invisible until the first `AA34`.
- Deposit measured against trailing spend, not a fixed threshold.
- A note in `--help`: `--paymaster` **takes a value**. Bare `--paymaster` sets the flag to the string
  `'true'` and `requireAddress` exits 1 (`doctor.ts:57-81`).

**Alarms:** deposit below N days of trailing spend; denied-rate spike (an attack or a tenant
misconfiguration — both want a human); reserved-vs-settled gap growing; signer key age.

**Runbooks to write before launch, not after:** rotate the signer
([§1.3](#13-the-cost-of-statelessness)); top up the deposit; kill sponsorship (stop signing, then
`withdrawTo`); onboard a tenant (including the [§4.3.4](#434-the-limit-of-targetselector-filtering)
target review); offboard a tenant.

---

## 8. Test matrix

### 8.1 Forge (`packages/contracts/test/`)

Greenfield — no existing test touches a paymaster. Use the harness at
`test/GianoSmartWallet/SmartWalletTestBase.sol:18-36`: `test/GianoSmartWallet/Static.sol` holds the
deployed EntryPoint v0.7 runtime bytecode for `vm.etch`, which also satisfies `BasePaymaster`'s ERC-165
constructor check.

| Case | Expectation |
|---|---|
| Valid grant | op sponsored, deposit debited |
| Tampered `callData` | `SIG_VALIDATION_FAILED`, **not** a revert |
| Raised `maxFeePerGas` | same — **the test that would have caught [§5.1](#51-two-blockers-in-the-current-client) blocker 2** |
| Raised any gas limit | same |
| Wrong signer | same |
| Expired / not-yet-valid | rejected on the time range, before execution |
| Replay of a consumed grant | rejected by the EntryPoint nonce |
| Grant from another chain id or another paymaster instance | `SIG_VALIDATION_FAILED` — proves the domain binding |
| `paymasterAndData` length ≠ 133 | `InvalidPaymasterDataLength` |
| `postOp` | never entered (assert via a `postOp` that would revert if reached) |
| Deposit exhausted | `AA31` from the EntryPoint |
| **Hash parity** | `getHash(...)` equals the digest an off-chain viem `encodeAbiParameters` + `hashTypedData` produces for the same inputs — a Solidity-side fixture asserted against a committed vector generated by the backend's own code. This is the test that catches a field-order divergence between [§2.4](#24-the-signed-struct) and the signer |

### 8.2 Vitest (`packages/wallet-core`)

**Harness prerequisite:** `test/helpers.ts:113-144`'s `createMockBundler` is hand-rolled and never runs
viem's `prepareUserOperation`, so it cannot exercise the paymaster hooks at all. Every ordering claim in
[§5](#5-client) is a claim about viem's internals, so add a helper that builds a **real** viem
`BundlerClient` over a fake transport. Free bonus: a transport that throws on unhandled methods means
any regression reintroducing viem's internal fee estimation fails loudly.

**Write this one first and confirm it fails on `main`:**

> the fees the grant covered are the fees that get submitted — assert
> `submitted.maxFeePerGas === grantRequest.userOperation.maxFeePerGas`.

Then: exactly one `final` and one `estimate` request per transaction; no bound field `undefined` at
mint time; the 800k `verificationGasLimit` floor is inside the grant; the returned paymaster gas limits
are authoritative even when the bundler suggests others; the stub's `paymaster` and `paymasterData`
appear in the `eth_estimateUserOperationGas` params; denial throws `GianoSponsorshipDeniedError` with
**zero** passkey prompts and no submission; the unsponsored path is unchanged; the embedded branch
sponsors and submits once; `eth_prepareUserOperation` mints exactly one grant; the
prepare→sign→sendSigned triad mints one grant total and prompts once; **`withValidation` exposes
`getSponsorship` when present and `undefined` when absent** ([§5.3](#the-three-file-rule)); tamper each
of the fourteen projected fields in turn and get a mismatch error naming that field; a `final`
`paymasterData` longer than the stub's throws.

`test/provider.test.ts:266-274` currently feeds an *unsigned* operation to
`eth_sendSignedUserOperation` and must be updated for the [§5.1](#51-two-blockers-in-the-current-client)
semantics change.

### 8.3 Vitest (`services/wallet-api`)

Via `startTestStack` + `envOverrides` (`test/setup.ts:119-147`) with `SPONSOR_SIGNER=local`. The
existing `register()` helper (`test/api.test.ts:42`) yields the session and wallet address.

Policy allow and deny; default-deny with an empty config; `executeBatch` with one unmatched call denied
wholesale; undecodable selector denied; sender binding; cross-tenant session rejection; `estimate` and
`final` return equal-length `paymasterData` and equal gas limits; **`initCode` reconstruction** from
`factory` + `factoryData` ([§3.1](#31-initcode-reconstruction--read-this-before-implementing-the-backend));
per-user and per-tenant budget exhaustion; two concurrent requests at the budget boundary — exactly one
succeeds; a repeated identical request returns the same grant and creates one reservation; seed-time
rejection of `enabled: true` with empty `rules`, of a duplicate `tenantId`, and of a `tenantId` change.

Plus pure unit tests for the KMS DER adapter: low-`s` normalisation, `v` recovery, and parity with
`privateKeyToAccount` for an identical digest.

### 8.4 Playwright (`e2e/`)

Extend the existing three-spec structure. `tenant-isolation.spec.ts:141-157` (V12) already has comments
saying "connect + **sponsored** tx" — this is what makes them true.

Sponsored transaction to receipt on both `stock` and `byo` against the real verifying paymaster; a
denial surfacing at the dApp as `send:error: rpc:-32010` via the existing `expectOutContains` shape;
one tenant's budget exhaustion leaving the other tenant sponsoring normally; a tenant with
`enabled: false` producing a clean denial rather than a hang.

---

## 9. Milestones

| M | Deliverable | Acceptance |
|---|---|---|
| **M0** | Client restructure: fees-first, single prepare, `eth_sendSignedUserOperation` fix, the regression test | The §8.2 fee test passes; hook-call counts are 1 stub + 1 final; e2e stays green on the **permissive** paymaster; no observable fee change (per the [§5.1](#51-two-blockers-in-the-current-client) probe) |
| M1 | Contract, forge suite, Ignition module, registry plumbing, devnet state regeneration script | §8.1 green including hash parity; `addresses.ts` and `generated.ts` drift checks pass; `state.json` reproducible from a committed script |
| M2 | Signer abstraction, migration `0003`, policy engine, endpoint, metrics, openapi | §8.3 green; `openapi:check` passes; boot fails loudly on a misconfigured signer |
| M3 | Injection hook, mint-once, invariant assertion, error codes, both SPAs rewired | §8.2 green in full; `wallet.ts` and `runtime.ts` net **shorter**; a denial reaches the dApp as `-32010` |
| M4 | e2e sponsored flows on both tenants; devnet drops `PermissivePaymaster` | §8.4 green; `GIANO_PAYMASTER_ADDRESS` gone from the e2e compose file |
| M5 | Reconciliation sweeper, doctor checks, alarms, runbooks, doc updates | Reserved-vs-settled gap converges in a soak run; `doctor` catches a deliberately mismatched signer; `ARCHITECTURE.md`, `COST-MODEL.md` §5.4, `MULTI-TENANCY-GAPS.md` D3.3, `PRODUCT-STRATEGY.md` §S4 and `TRANSACTION-SUBMISSION-FLOW.md` all reconciled |

M0, M1 and M2 each ship independently — M0 is behaviour-preserving, and M1/M2 add code nothing calls
yet. M3 needs M1 and M2. A staging run with Alto `--safe-mode true` gates any funded chain
([§1.3](#13-the-cost-of-statelessness)).

---

## 10. Corrections to PAYMASTER-DESIGN.md

Recorded here so the design document's revision history is traceable. All are applied in that file.

| § | Correction |
|---|---|
| 4.1 | The shared-ledger contract is now **v2**. v1 has no ledger, no daily cap, no signer set and no `pause()`, because each is an `SLOAD` in validation and would forfeit the stake exemption ([§1.3](#13-the-cost-of-statelessness)) |
| 4.2 | Add the `factory`/`factoryData` → `initCode` reconstruction rule ([§3.1](#31-initcode-reconstruction--read-this-before-implementing-the-backend)) |
| 4.3 | The `paymaster: {...}`-in-`wallet.ts` wiring is wrong on three counts; it belongs on the injection ([§5.3](#53-where-the-sponsorship-fetch-lives)). Also: the stub must return both paymaster gas limits, and `final`'s are the signed ones |
| 4.5 | Rewritten for the pluggable signer. v1 rotation is redeploy-and-drain, not `addSigner` — but cheaper than the doc feared, since the endpoint returns the address |
| 5 | The sequence diagram has two steps swapped: viem fills fees **before** the stub hook, so the order is resolve fees → stub → estimate → final |
| 6.1 | Names only half the blocker. The redundant top-level `estimateUserOperationGas` is the larger half, and `eth_sendSignedUserOperation` re-prepares and re-signs |
| 6.3 | `config.json`'s `paymasterAddress` stays for devnet, with a construction-time warning when both it and sponsorship are configured |
| 7, 8 | v1 has **no** on-chain circuit breaker (blast-radius rows revised), and `consume` is unreachable on the embedded/BYO path, so settlement is receipt-driven |
| 11 | Decisions 3, 4 and 5 resolved. Decision 5 (stake) is moot for v1 by construction |
