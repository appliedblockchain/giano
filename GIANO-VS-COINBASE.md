# Giano vs. the Coinbase libraries it forked

**Date:** 2026-07-23
**Question:** What does Giano's self-hosted solution give you that the upstream
Coinbase stack does not — and what does it cost you — with a focus on **vendor
lock-in, cost, and network compatibility**.

---

## 1. TL;DR

Giano and Coinbase Smart Wallet share **the same on-chain wallet** — Giano's
Solidity is a near-verbatim fork of `CoinbaseSmartWallet` (same signature scheme,
same passkey/P256 validation, same MultiOwnable/ERC-1271 core). Everything that
differs is **off-chain**: who runs the wallet origin, the bundler, the credential
store, and the gas.

- **Coinbase path** = you plug into Coinbase's *hosted product* (the
  `keys.coinbase.com` shared wallet + Coinbase Developer Platform bundler/paymaster).
  Near-zero infra to run, free gas sponsorship tiers, a huge existing user base —
  but you inherit **hard runtime dependencies on Coinbase infrastructure** and a
  strong gravitational pull toward **Base**.
- **Giano path** = you *self-host the entire wallet stack* (wallet-web, wallet-api,
  Postgres, bundler) as containers in your own infrastructure. **No Coinbase runtime
  dependency, deployable on any EVM chain**, wallets bound to *your* origin — but
  you carry the **operational cost and burden** (services to run, a bundler
  executor account to fund, no gas sponsorship out of the box).

The choice is essentially **managed convenience + ecosystem lock-in (Coinbase)**
vs. **operational ownership + independence (Giano)**.

---

## 2. What "the Coinbase libraries" means here

Giano forked from Coinbase's open-source **[coinbase/smart-wallet](https://github.com/coinbase/smart-wallet)**
contracts. But the contracts are only part of Coinbase's offering. The realistic
"do it with Coinbase" alternative is the whole product surface:

| Layer | Coinbase's version | Giano's version |
|---|---|---|
| Smart-account contracts | `CoinbaseSmartWallet` + factory (MIT, open) | `GianoSmartWallet` fork (MIT) — see §7 |
| Wallet origin (passkey UI, RP) | **Hosted** `keys.coinbase.com` (shared, Coinbase-operated) | **Self-hosted** `giano-wallet-web` container = `wallet.yourapp.com` |
| dApp SDK | `@coinbase/wallet-sdk` / Base Account SDK | `@appliedblockchain/giano-connector` (thin EIP-1193 / wagmi / RainbowKit) |
| Credential registry / WebAuthn server | Coinbase-operated | `giano-wallet-api` (Fastify + Postgres + `@simplewebauthn/server`) |
| Bundler | Coinbase Developer Platform (managed) | Self-hosted **Pimlico Alto** (`@pimlico/alto`, pinned) or any bundler you point at |
| Paymaster / gas sponsorship | Coinbase Developer Platform paymaster (managed, free tiers) | **None bundled** — you deploy/fund your own (only a testing paymaster ships) |

The transport layer is the same idea in both: a JSON-RPC-over-`postMessage` popup
to a wallet origin that holds the passkey account. Giano's `giano-wallet-transport`
is explicitly "modeled on the keys.coinbase.com postMessage pattern" — reimplemented
so it points at *your* origin instead of Coinbase's.

---

## 3. Architecture at a glance

**Coinbase:** dApp → `@coinbase/wallet-sdk` → popup to **Coinbase-hosted**
`keys.coinbase.com` → Coinbase credential store + Coinbase bundler/paymaster →
EntryPoint v0.6* → `CoinbaseSmartWallet`.

**Giano:** dApp → `@appliedblockchain/giano-connector` → popup to **your-hosted**
`wallet.yourapp.com` (`giano-wallet-web`) → `giano-wallet-api` + Postgres →
self-hosted Alto bundler → EntryPoint v0.7 → `GianoSmartWallet`.

The trust boundary is the same shape (dApp never holds keys; wallet origin does);
the difference is **who operates the origin and the infra behind it**.

\* Coinbase's public deployments have historically targeted EntryPoint v0.6; Giano
moved the fork to **v0.7** (see §7).

---

## 4. Vendor lock-in

### 4.1 Coinbase path — where the hooks are

- **Hosted wallet origin.** With `keys.coinbase.com`, the WebAuthn Relying Party is
  Coinbase's domain. Users' passkeys are bound to *Coinbase's* origin, and the
  consent UI, credential recovery, and account model are Coinbase-operated. You do
  not control that origin, its uptime, its UX, or its policies — and you cannot
  migrate the credentials off it (passkeys are non-exportable and RP-bound).
- **Managed bundler/paymaster.** Gas sponsorship and user-op submission run through
  Coinbase Developer Platform endpoints (API-keyed). This is a **runtime dependency
  on a third party**: their availability, rate limits, pricing changes, and chain
  support gate your app. Notably, Giano's own gap analysis records that **in
  production only the Coinbase managed bundler had ever worked** for Giano user-ops
  — a concrete example of how easy it is to end up silently coupled to Coinbase's
  infra even when the contracts are "open."
- **Base gravity.** The whole Coinbase AA stack is optimized for and steered toward
  **Base**. The contract even carries `REPLAYABLE_NONCE_KEY = 8453` (Base's chain
  ID) as a magic constant. Chains Coinbase doesn't support = no managed
  bundler/paymaster there.
- **Shared account namespace.** Users get *one* Coinbase Smart Wallet shared across
  every dApp that integrates it — great for onboarding, but it means the user
  relationship and the account live in Coinbase's system, not yours.

**Escape cost:** low code lock-in (contracts are MIT and open), but **high
operational/credential lock-in** — moving off `keys.coinbase.com` means new
passkeys (users re-register) and standing up all the infra Coinbase was giving you
for free. That is exactly the project Giano represents.

### 4.2 Giano path — what it removes and what it adds

- **No Coinbase runtime dependency.** The three SDK packages contain **no
  `@coinbase/*` or `@base-org/*` deps, no `permissionless`, no hardcoded Coinbase
  endpoints**. The services (wallet-api, wallet-web, bundler, devnet) reference no
  Coinbase infra. The only residual Coinbase string in the whole codebase is a
  borrowed WebAuthn *stub signature* used for gas estimation — not a live endpoint.
  (The one Coinbase CDP bundler URL that exists is in the **demo dApp's** sample env
  file and is trivially swappable.)
- **You own the origin.** Passkeys bind to *your* `wallet.yourapp.com`; the RP ID,
  consent UI branding, credential store (your Postgres), and user model are yours.
- **You own the account relationship.** Wallets are scoped per deployment — no
  shared cross-project namespace, which is the flip side of the trade (see §8).
- **Standards, not proprietary rails.** Canonical ERC-4337 EntryPoint v0.7, viem
  `SmartAccount`, EIP-1193 / wagmi / RainbowKit. Any ERC-4337 bundler can be
  swapped in; the wallet-api treats the bundler URL as a pluggable endpoint.

**New lock-in Giano introduces (be honest about it):**
- **GitHub Packages, restricted scope.** The npm packages publish to
  `npm.pkg.github.com` with `access: restricted` under `@appliedblockchain` — so
  consuming them requires GH Packages auth, and routing the whole `@appliedblockchain`
  scope there conflicts with pulling other public `@appliedblockchain/*` packages
  from npmjs. This is a distribution constraint, not a runtime one.
- **Self-coupling to the Giano services.** Your dApp is now coupled to *your own*
  wallet-api/wallet-web contract and its versioning (single-semver lockstep,
  DB-migration ordering). You've traded a dependency on Coinbase for a dependency on
  a stack you operate — which is the point, but it is not "zero dependency."

**Net:** Giano converts **external vendor lock-in** into **internal operational
ownership**. Strictly better for sovereignty and auditability; strictly more work.

---

## 5. Costs

### 5.1 Coinbase path

- **Infra you run:** essentially none — just your dApp bundle + the `@coinbase/wallet-sdk`.
- **Gas:** Coinbase's managed paymaster offers **sponsored gas** (free tiers, then
  usage-based via Coinbase Developer Platform). This is the single biggest cost
  advantage — you don't have to fund an on-chain executor or run a paymaster.
- **Bundler/RPC:** included in the managed platform (subject to their rate
  limits/pricing).
- **Hidden cost:** pricing, quotas, and chain support are Coinbase's to change; and
  the eventual **exit cost** (re-registering users, building infra) if you ever need
  off it.

**Cost profile: low fixed cost, low ops headcount, external pricing risk.**

### 5.2 Giano path

You run and pay for everything the managed platform was giving you:

| Component | What it costs |
|---|---|
| **Postgres 17** | Persistent DB (credentials, sessions, audit rows) — managed DB or self-run + backups |
| **wallet-api** | Always-on Node service (Helm defaults to 2 replicas) |
| **wallet-web** | Always-on nginx/SPA origin (2 replicas) — this is the WebAuthn RP, needs its own TLS host |
| **Bundler (Alto)** | Always-on service **+ a funded executor account** — the executor key signs and pays for every bundle on-chain, so you fund it with native gas continuously |
| **RPC node** | Self-run or a paid RPC provider endpoint (`RPC_URL`) |
| **Gas sponsorship** | **Not included.** Only a testing `PermissivePaymaster` ships; production sponsorship = deploy and fund your own paymaster |
| **One-shot** | Contract deployment per target chain (`giano-contracts-deployer` job) + P256/CREATE2 bootstrap on chains that need it |

Plus the human cost: TLS/DNS for the wallet subdomain, secrets management (executor
keys, admin API keys), DB migrations, monitoring, and lockstep upgrades across
SDK ↔ api ↔ web ↔ DB.

**Cost profile: meaningful fixed infra + ops cost, no external pricing risk, no
free gas.** The break-even vs. Coinbase depends entirely on scale and on how much
you value independence — at low volume Coinbase's free tiers are hard to beat on
pure cost; at scale, on non-Base chains, or where you *cannot* depend on a third
party, self-hosting wins.

---

## 6. Network / chain compatibility

This is where Giano's fork earns its keep.

### 6.1 Coinbase path

- **Practically Base-centric.** The managed bundler/paymaster and the hosted wallet
  are built around Base (and a limited set of chains Coinbase chooses to support).
  On any chain Coinbase doesn't serve, the managed conveniences simply aren't there.
- The **contracts** themselves are chain-agnostic (it's standard ERC-4337), but the
  *product* is only as portable as Coinbase's infra coverage.

### 6.2 Giano path — genuinely chain-agnostic EVM

- **Chain is pure config.** `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL`, and optional
  `ENTRYPOINT_ADDRESS`/`FACTORY_ADDRESS` drive the stack. Ships address-registry
  defaults for **Base (8453)**, **Base Sepolia (84532)**, and an Applied Blockchain
  devnet (**381185**, Silent Data Rollup); any other chain just needs the addresses
  supplied.
- **P256 works on any EVM chain — no precompile required.** WebAuthn verification
  tries the **RIP-7212 precompile** at `0x100` for cheap gas *where it exists*, then
  **falls back to pure-Solidity FreshCryptoLib** where it doesn't. So passkey wallets
  run even on chains without native P256 support (you just pay more gas there).
- **Deterministic addresses across chains.** CREATE2 via Hardhat Ignition with a
  fixed salt and pinned compiler settings gives the **same factory/implementation
  address on every chain** deployed with the canonical build (verified identical on
  8453/84532/31337). A bundled deployer script can bootstrap the CREATE2 factory and
  a P256 verifier on fresh chains.
- **No chain lock in the contract logic.** The only hardcoded on-chain address is
  the canonical ERC-4337 v0.7 EntryPoint (identical on all EVM chains); the `8453`
  nonce-key constant is a Coinbase leftover used purely for nonce partitioning, not
  a network guard.

**Bottom line:** Coinbase is the easy path *if you live on Base*. Giano is the path
if you need passkey smart wallets on **arbitrary EVM chains** — app-chains, L2s
Coinbase doesn't serve, or a private/rollup chain (which is exactly Applied
Blockchain's Silent Data Rollup case).

> **Caveat carried from Giano's own analysis:** self-hosted bundler compatibility on
> public networks was historically unproven (production had only ever cleared
> through Coinbase's bundler). If you go the Giano route on a new chain, validate the
> full create → sign → submit flow against your chosen bundler early — this is the
> one place the "runs anywhere" claim needs empirical confirmation per chain.

---

## 7. Where they are identical (the forked core)

Giano's contracts are a faithful fork of Coinbase Smart Wallet — same
`SignatureWrapper` scheme, 32-byte EOA owners via `SignatureCheckerLib` and 64-byte
P256 owners via `WebAuthn.verify`, same `MultiOwnable` + ERC-1271 + UUPS core, same
Solady/LibClone deterministic factory. Attribution to Coinbase and Solady is
preserved in the NatSpec. Meaningful **divergences**:

- **EntryPoint v0.6 → v0.7** (PackedUserOperation, v0.7 singleton).
- **Added upgrade-safety check** — replayable batches revert if an
  `upgradeToAndCall` targets a codeless implementation.
- **New `AuthenticatedStaticCaller`** — `signedStaticCall` with a 30-minute
  signature lifetime (not in upstream; still carries a `TODO: make configurable`).
- **Rebranding** — EIP-712 domain `Giano Smart Wallet`, ERC-7201 namespace
  `appliedblockchain.storage.MultiOwnable`, etc. (functionally equivalent, different
  hashes/addresses).
- Kept **`REPLAYABLE_NONCE_KEY = 8453`** verbatim.

Because the wallet primitive is essentially the same, **the comparison is not about
smart-contract capability — it's about operating model.**

---

## 8. Trade-off summary

| Dimension | Coinbase (hosted) | Giano (self-hosted) |
|---|---|---|
| **Runtime vendor lock-in** | High — hosted wallet + bundler + paymaster | **None on Coinbase**; internal coupling to your own stack |
| **Credential ownership** | Passkeys bound to `keys.coinbase.com` | Passkeys bound to **your** origin |
| **Distribution lock-in** | Public npm | GitHub Packages, restricted scope |
| **Infra to run** | ~None | Postgres + api + web + bundler + RPC |
| **Gas sponsorship** | Managed paymaster, free tiers | **Bring your own** (fund executor / deploy paymaster) |
| **Fixed cost / ops** | Low | Meaningful |
| **External pricing risk** | Yes | No |
| **Network reach** | Base-centric / Coinbase-supported chains | **Any EVM chain** (RIP-7212 or FCL fallback) |
| **Deterministic cross-chain address** | Yes | Yes |
| **Shared user base / onboarding** | **Yes** — existing Coinbase wallet users | No — wallets scoped to your deployment |
| **Auditability / sovereignty** | Trust Coinbase | **Full control, self-auditable** |
| **Time to integrate** | Fastest | Slower (deploy a stack) |

---

## 9. Recommendation

**Choose the Coinbase stack when:** you're building on Base, want the fastest
integration, want free/managed gas sponsorship, and value tapping Coinbase's
existing wallet user base more than you fear the dependency. Lowest cost and effort
at small-to-medium scale.

**Choose Giano when any of these are true:**
- You must run on a **chain Coinbase doesn't serve** (app-chains, other L2s,
  private/rollup chains — e.g. Silent Data Rollup).
- You **cannot accept a third-party runtime dependency** for the wallet, bundler, or
  credential store (regulatory, sovereignty, data-residency, or reliability reasons).
- You want passkeys and the user relationship **bound to your own brand/origin**, not
  Coinbase's.
- You want the whole trust path **self-auditable and versioned** in your own infra.

In short: Giano is the deliberate **de-risking of Coinbase lock-in** — you keep the
proven Coinbase wallet contract, and you take on running everything Coinbase
otherwise runs for you. The bet pays off precisely when independence and
multi-chain reach matter more than managed convenience and free gas.

---

### Evidence base

Contracts: `packages/contracts/src/*.sol`, `addresses.ts`, `hardhat.config.ts`,
`ignition/deployments/*`. SDK: `packages/{connector,wallet-core,wallet-transport}/`.
Services: `services/{wallet-api,wallet-web,bundler,devnet}/`, `deploy/*`. Project's
own analysis: `GAPS-TO-COMPLETION.md` (esp. §3, bundler lock-in), `COMPATIBILITY.md`,
`specs/DEVELOPER-GUIDE.md`, `specs/INTEGRATION.md`.
