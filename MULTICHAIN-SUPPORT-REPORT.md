# Multi-chain support in Giano — what it would take

**Scope.** Today every Giano transaction lands on one chain, fixed by deployment configuration.
This report inventories exactly where that single chain is nailed down, distinguishes the layers
that are already chain-parameterised from the ones that are genuinely single-chain, sets out the
invariants any design has to respect, and presents four viable designs (plus one out-of-scope
direction) with trade-offs, so a choice can be made before any code moves.

Written against `experimental_no_bundler` at `03ae535`.

---

## 1. Executive summary

Giano is **not uniformly single-chain**. The three layers have very different readiness:

| Layer | State | Why |
|---|---|---|
| **Contracts + address registry** | **Already multi-chain** | `gianoAddresses` is keyed by chain id; CREATE2 gives one address per owner set across chains; `executeWithoutChainIdValidation` already exists to replay owner-set changes onto every chain |
| **Sponsorship / paymaster stack** | **Already chain-parameterised, fed one constant** | Every sponsorship table carries `chain_id` — most in the primary key — and every service takes `chainId` as an argument. It is passed `config.CHAIN_ID` and nothing else |
| **wallet-api process, wallet-web runtime, transport protocol, thin SDK** | **Genuinely single-chain** | Scalar `CHAIN_ID` / `RPC_URL` / `BUNDLER_URL`; one `config.json` with scalar `chainId`; the handshake carries no chain at all; the SDK takes exactly one `chain` |

The consequence: **the request as stated — "the SDK selects the chain" — is the small half of the
job.** The wire-protocol change is a handful of fields. The real work is (a) making one wallet-api
process serve N chains, (b) per-chain bundler and paymaster operations, and (c) deciding what a
"wallet" means when the smart-account address is not guaranteed identical across chains.

There is also **one latent bug** that multi-chain will expose: `wallet_switchEthereumChain` is
already implemented in `wallet-core` (`provider.ts:396`) and already wired through the wagmi
connector (`connector.ts:65`), but it swaps only the *read* client. The bundler client, the
paymaster hooks and the factory address stay bound to the chain the provider was constructed with.
Today that is harmless because `chains` always has length 1. The moment it has length 2, a chain
switch silently submits user operations to the wrong chain's bundler.

**Recommendation (detail in §7):** Option B (chain fixed per SDK instance, declared in the
handshake) as the shippable milestone, evolving to Option C (native `wallet_switchEthereumChain`)
once B is stable, with Option D (`provider.forChain()`) added as an escape hatch for dApps that
need to address two chains concurrently. Option A is cheap but produces a materially worse product
and should only be considered as a stopgap.

---

## 2. Inventory — every place the single chain is pinned

### 2.1 Layer 0 — Contracts *(no change required)*

| Item | Location | Note |
|---|---|---|
| Address registry | `packages/contracts/addresses.ts:33` | `Record<number, GianoDeployment>` — already per-chain. Chains 8453, 84532, 381185 registered |
| Factory `getAddress(owners, nonce)` | `GianoSmartWalletFactory.sol` | Deterministic; address depends on **factory address**, owners and nonce — *not* on chain id |
| Cross-chain owner sync | `GianoSmartWallet.sol:54`, `:210`, `:277` | `REPLAYABLE_NONCE_KEY = 8453` + `executeWithoutChainIdValidation` already allow one signed op to add/remove an owner or upgrade on every chain |
| Anti-replay for normal ops | `ERC1271.sol` `replaySafeHash`, `toGianoSmartAccount.ts:309` | EIP-712 domain includes `chainId` — ordinary signatures do **not** cross chains. Correct as-is |
| Paymaster authorisation domain | `sponsorship-signer.ts:70` | `{ name: 'GianoPaymaster', chainId, verifyingContract }` — already domain-separated per chain and per paymaster instance |
| Deployment | `hardhat.config.ts`, `ignition/deployments/chain-*` | Per-chain Ignition deployments already committed |

**Gap:** `determinism.yml` only asserts the CREATE2 addresses against the Base (8453) registry. And
the registry itself shows **381185 has a different factory address** from 8453/84532 — see §4.2, this
is the single most consequential open question.

### 2.2 Layer 1 — `wallet-core` provider

| Pin | Location |
|---|---|
| `initialChainId: number` — one starting chain | `provider.ts:75`, bootstrapped at `:618` |
| `bundler: BundlerClient` — **one** bundler, constructed by the caller and bound to one chain + one URL | `provider.ts:77` |
| `gianoSmartWalletFactoryAddress: Address` — **one** factory, so one chain's deployment | `provider.ts:80` |
| `wallet_switchEthereumChain` swaps `chain`, `transport`, `client` only — **not** the bundler, paymaster hooks or factory | `provider.ts:396–415` |
| `wallet_addEthereumChain` is a `// TODO: implement` stub returning `null` | `provider.ts:393` |
| WebAuthn user id encodes a single `chainId` + `ChainType` byte at credential creation | `provider.ts:44`, `:509`; `provider-injection/injection.ts:38`; `types/decoded-user-id.ts` |

**Already good:** `chains: readonly Chain[]` and `transports: Record<number, Transport>` are already
plural. `toGianoSmartAccount` derives its chain id from `client.chain.id`
(`toGianoSmartAccount.ts:185`, `:204`, `:223`, `:242`) and holds no global chain state — so a
per-chain account instance costs nothing structurally.

### 2.3 Layer 2 — `wallet-web` (the wallet origin)

| Pin | Location |
|---|---|
| `WalletConfig` has scalar `chainId`, `rpcUrl`, `bundlerUrl`, `factoryAddress`, `paymasterServiceUrl`, `testPaymasterAddress` | `src/config.ts:7–33` |
| `loadWalletConfig` validates exactly one chain and resolves one registry entry | `src/config.ts:39–52` |
| `config.json` / `config.json.template` are flat, one chain | `public/config.json`, `docker/config.json.template` |
| `createWalletRuntime` builds one `defineChain`, one public client, one bundler client, one paymaster hook set, one `WalletRuntime.chainId` | `src/wallet.ts:101`, `:124`, `:136`, `:154`, `:209` |
| Runtime is created once at boot from one config | `src/main.tsx` |
| Settings shows a bare chain id, no name | `src/views/Settings.tsx:73` |
| Consent screens (`ReviewTransaction`) do not display which chain is being approved | `src/views/ReviewTransaction.tsx` |

The same pins exist in the BYO-wallet reference (`e2e/wallet-byo/src/config.ts`), which tenants are
told to copy — so its shape is effectively public API.

### 2.4 Layer 3 — `wallet-transport` (the dApp ↔ wallet wire)

**The handshake carries no chain information whatsoever.** `handshakeMessageSchema`
(`protocol.ts:32`) carries `{ sdkVersion, capabilities }`; `handshakeAckMessageSchema` (`:42`)
carries `{ walletVersion, capabilities }`. The wallet origin therefore decides the chain
unilaterally, from its own `config.json`, and the dApp has **no way to state a preference and no way
to detect a mismatch**. If a dApp is built for Base and the wallet origin is configured for
Base Sepolia, the transaction silently goes to the wrong chain.

There is no method allowlist in `TransportHost` (`host.ts:127` forwards any method), so new methods
need no protocol change — only the handshake does.

### 2.5 Layer 4 — thin SDK / connector

| Pin | Location |
|---|---|
| `CreateGianoWalletProviderParams.chain: Chain` — exactly one, no list | `create-giano-wallet-provider.ts:8` |
| One read-path `publicClient` for that chain | `:63–66` |
| `wallet_switchEthereumChain` is **not** in `WALLET_METHODS` and has no special case → it falls to the read path and is sent to an HTTP RPC transport, which cannot honour it | `:28–38`, `:222` |
| `eth_chainId` answers from the cached session or the constructed chain | `:180` |
| wagmi connector's `switchChain` calls `wallet_switchEthereumChain` — i.e. **the connector already advertises a capability the provider does not implement** | `connector.ts:65–68` |

**Already good:** the session cache key is already namespaced per wallet origin **and** chain
(`:59`), with a migration from the legacy unnamespaced key — so per-chain session state needs no
storage redesign. `chainChanged` is already plumbed end-to-end: `wallet-core` emits it
(`provider.ts:414`), `wallet-web` relays it (`host.ts:57`), the thin provider forwards it (`:101`).

### 2.6 Layer 5 — `wallet-api` (the hard part)

| Pin | Location |
|---|---|
| `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL` are scalar required env vars; `ENTRYPOINT_ADDRESS` / `FACTORY_ADDRESS` default from the registry for that one chain | `config.ts:71–77`, `:167`, `:233` |
| One `BundlerService` (one URL, one EntryPoint) for the whole process | `app.ts:65` |
| One `publicClient` (`RPC_URL`) shared by WebAuthn address computation and the paymaster reader | `app.ts:66` |
| One `PaymasterReader` at one address | `app.ts:121` |
| One `SponsorshipService`, constructed with `chainId: config.CHAIN_ID` | `app.ts:129` |
| Relay hashes the op against `config.CHAIN_ID` | `routes/userops.ts:136` |
| ERC-7677 route **receives** `chainId` in the params and **rejects** anything but the configured chain | `routes/paymaster.ts:200–204` |
| Admin sponsorship routes hard-bind `const chainId = config.CHAIN_ID` | `routes/admin-sponsorship.ts:38` |
| `/v1/version` returns one `chainId` (OpenAPI contract; CI has a drift check) | `routes/health.ts:59–60` |
| One paymaster watcher, one chain | `index.ts:48–61` |
| `computeWalletAddress` reads one factory on one client | `services/wallet-address.ts` |

Note that the ERC-7677 route already *speaks* a multi-chain protocol — the chain id is on the wire
per request, per spec. It just refuses everything but one value. That is a one-line change once
there is a per-chain service to route to.

### 2.7 Layer 6 — database schema

**Already chain-scoped** (`db/schema.ts`) — `chain_id` present, and in the primary key where it
matters:

- `tenant_sponsorship` (PK `tenant_id, chain_id`)
- `tenant_sponsorship_history`
- `paymaster_tenants` (PK `tenant_id, chain_id`)
- `sponsorship_reservations` (indexed on `tenant_id, chain_id, state`)
- `sponsorship_settlements` (PK `chain_id, userop_hash`)
- `sponsorship_decisions`
- `paymaster_state` (PK `chain_id`)

**Not chain-scoped:**

- `credentials.wallet_address` — a **single** address column per credential (`schema.ts:73`). This
  is the crux: it encodes the assumption that a passkey has exactly one wallet address. See §4.2.
- `userop_log` — no `chain_id`. `userop_hash` is globally unique, which remains *correct* (the hash
  commits to the chain id, so no collision), but the relay audit trail cannot answer "which chain"
  without joining through the sponsorship decision, and only sponsored ops have one.
- `sessions` / `users` / `challenges` — chain-agnostic, and should stay that way (see §4.1).

### 2.8 Layer 7 — infrastructure and operations

- One bundler (Alto) per chain is unavoidable — `deploy/docker-compose.*.yml`,
  `deploy/helm/giano/values.yaml` and `templates/*.yaml` all assume one.
- `GIANO_CHAIN_ID` / `GIANO_RPC_URL` / `GIANO_BUNDLER_URL` flow as scalars through
  `wallet-web/docker/entrypoint.sh` into the rendered `config.json`.
- The contracts-deployer job (`deployer-job.yaml`, `deployer-entrypoint.sh`) is one-chain-per-run.
- Each chain's bundler needs its own funded executor EOA; each chain's paymaster needs its own
  EntryPoint deposit and stake. This is a real, recurring operational cost per added chain, not a
  config change.
- Prometheus metrics carry no `chain` label — cardinality and dashboards both need revisiting.

### 2.9 Already-multi-chain precedent worth copying

`services/paymaster-admin/src/config.ts` already models exactly the shape the rest of the system
needs: a **runtime-fetched list of deployments**, each with `{ label, chainId, rpcUrl,
paymasterAddress, refreshSeconds }`, with an operator picker, and with the explicit reasoning that
the list "is the whole of what it can reach: an operator picks between environments someone
deliberately configured, and cannot point the console at an arbitrary chain by typing into it."

That is the right security posture and the right config shape for `wallet-web`'s `config.json` and
for `wallet-api`'s env. **Reuse it rather than inventing a second idiom.**

---

## 3. What we get for free

1. **The address registry is already per-chain** and `getGianoDeployment(chainId)` already exists.
2. **The whole sponsorship data model and service layer is already chain-parameterised.** Making it
   multi-chain is threading a value that is already a parameter, not a schema migration.
3. **The ERC-7677 protocol already carries the chain id per request.** No wire change needed there.
4. **`chainChanged` is already plumbed end-to-end** through all three hops.
5. **Session storage is already keyed per chain** in the thin SDK.
6. **`toGianoSmartAccount` is chain-agnostic per instance** — it reads the chain from its client.
7. **The contract already supports cross-chain owner-set replay**, which is what keeps a passkey
   added on one chain from being invisible on the others.
8. **The handshake already has a `capabilities` array** in both directions — a natural, non-breaking
   place to negotiate chain support.

---

## 4. Invariants any design must respect

### 4.1 Passkey identity is per-origin, never per-chain

The RP ID is the wallet origin's host, it is immutable once a tenant's first passkey exists
(`schema.ts` `tenants.rpId`, "IMMUTABLE once the tenant's first passkey exists"), and the browser
enforces it. **A passkey therefore belongs to a wallet origin, not to a chain.** Any design that
gives each chain its own origin gives each chain its own passkey — which is a different wallet per
chain from the user's point of view, and no amount of UI can hide that. This is what makes Option A
(§5.1) structurally weak.

Corollary: `users`, `credentials`, `sessions` and `challenges` must stay chain-agnostic. Do **not**
add `chain_id` to them.

### 4.2 The wallet address is chain-invariant only if the factory address is

`computeWalletAddress` is `factory.getAddress(owners, nonce)` — a function of the **factory
address**, owners, and nonce. Chain id does not enter. So the same passkey yields the same wallet
address on every chain **where the factory sits at the same address**.

The registry currently says:

- 8453 (Base) → factory `0x26dCd293…7050`
- 84532 (Base Sepolia) → factory `0x26dCd293…7050` — same
- 381185 → factory `0x3451C877…6191` — **different**

So the invariant *does not currently hold across all registered chains*. CREATE2 determinism holds
only when the deployer, the salt and the bytecode are byte-identical, and 381185 evidently diverged.

**This single fact decides the product:**

| If factory address is uniform across every target chain | If it is not |
|---|---|
| One wallet, one address, N chains. `credentials.wallet_address` stays as-is. The UI says "your wallet". Cross-chain owner sync via `executeWithoutChainIdValidation` keeps the owner sets identical. | A passkey maps to N addresses. `credentials.wallet_address` must become a `credential_wallets(credential_id, chain_id, wallet_address)` table. The UI must show a per-chain address. Sponsorship, policy and the session's `walletAddress` all become chain-qualified. Materially more work and a worse product. |

**This is decision #1 and it gates the schema.** The cheap answer is to make it an enforced
invariant: refuse to register a chain whose factory address differs from the canonical one, and
extend `determinism.yml` to assert it for every registered chain rather than only Base.

### 4.3 Money does not cross chains

The paymaster is one contract per chain, with its own EntryPoint deposit, its own treasury, its own
per-tenant balances and its own EIP-712 domain. A tenant's balance on chain A cannot pay for gas on
chain B without a bridge. The schema already models this correctly (`paymaster_tenants` PK is
`tenant_id, chain_id`). Any "unified balance" story is a separate product, not a refactor — see
§5.5. What *can* be shared is the **signing key**: one key can authorise on many chains safely,
because `authorisationDomain(chainId, paymaster)` separates them.

### 4.4 Signatures must not cross chains — except deliberately

`replaySafeHash` binds ordinary signatures to `(chainId, account)`. The one deliberate exception is
`executeWithoutChainIdValidation`, gated to owner add/remove and `upgradeToAndCall`
(`canSkipChainIdValidation`, `GianoSmartWallet.sol:277`), using `REPLAYABLE_NONCE_KEY`. If
multi-chain is adopted, that path stops being a curiosity and becomes the mechanism that keeps owner
sets in sync — it needs to be exposed, tested per chain, and reflected in the consent UI ("this
change applies to every chain").

### 4.5 The user must be told which chain they are approving

Consent is the whole point of the wallet origin. `ReviewTransaction` currently shows no chain, which
is defensible when there is only one. With N chains, chain identity must appear on the consent
screen alongside target and value, and a chain switch must invalidate any in-flight preflight
(including the sponsorship preflight, `wallet.ts:170`) — a "will be sponsored" answer computed on
chain A is meaningless on chain B.

### 4.6 The chain-tagged WebAuthn user id becomes a liability

`encodeUserId(id, factoryAddress, chainId, chainType)` stamps a chain id into the credential's user
handle at creation time (`provider.ts:509`). Nothing enforces it today, but it means a credential
created "on Base" decodes as Base forever, even when used on Optimism. Either retire the field
(keep the byte for layout compatibility, stop reading it) or redefine it as "chain of first use,
informational". Leaving it as-is invites a future consumer to enforce it and break multi-chain.

---

## 5. The options

### 5.1 Option A — One stack per chain ("chain ≡ wallet origin")

Deploy the existing single-chain stack N times. The SDK "selects the chain" by selecting the
`walletUrl` it points at.

**Changes:** essentially none in code. N× wallet-web, N× wallet-api (or N× tenant rows across N
databases), N× bundler, N× deploy pipeline.

**Pros**
- Zero protocol, SDK, schema or service change. Shippable this week.
- Perfect blast-radius isolation: a bad chain cannot affect another.
- Per-chain policy, rate limits and paymaster config come free (they are per-tenant already).

**Cons**
- **Fatal for UX: a different RP ID per origin means a different passkey per chain** (§4.1). The user
  registers, and re-registers, per chain. "Your wallet" becomes "your four wallets".
- Cost scales linearly and never amortises: N Postgres, N wallet-api, N TLS host, N tenant onboarding.
- A dApp wanting two chains must instantiate two providers against two origins and manage two
  sessions — the multi-chain problem is pushed onto every integrator.
- *Partial mitigation:* Related Origin Requests (`README-ROR.md`, `ror_origins`) lets several
  origins share one RP ID, which would let the passkey follow the user across chain origins. But
  `tenants.rp_id` is `UNIQUE` and the tenant model is "tenant ≡ wallet origin ≡ RP ID", so this
  cuts against the grain of the current design and is not a small change.

**Verdict:** legitimate as a stopgap for two unrelated environments (e.g. a testnet and a mainnet
deployment, which is arguably what it already is). Not an answer to "one user, several chains".

### 5.2 Option B — Chain fixed per SDK instance, declared in the handshake ★

The wallet origin serves N chains. The dApp states its chain at SDK construction; the SDK declares
it in the handshake; the wallet origin instantiates (or looks up) the runtime for that chain, or
refuses with a clear error. **No mid-session switching.**

**Changes**

*`wallet-transport`* — additive, backward-compatible:
```ts
handshakeMessageSchema.payload  += { chainId?: number }        // dApp's requested chain
handshakeAckMessageSchema.payload += { chainId: number,        // the chain actually granted
                                       supportedChainIds: number[] }
```
An absent `chainId` means "whatever you're configured for" — so existing dApps keep working. A
requested chain the wallet does not serve is refused at handshake with `CHAIN_DISCONNECTED` (4901,
already in `RPC_ERRORS`) and the list of chains it does serve.

*`connector` (thin SDK)* — `chain: Chain` stays; pass `chain.id` into `TransportClient`'s handshake;
surface a typed error on refusal. Session key already per-chain. ~30 lines.

*`wallet-core`* — replace the single `bundler: BundlerClient` with a per-chain lookup
(`bundlers: Record<number, BundlerClient>` or a `getBundler(chainId)` factory), and make the factory
address per-chain (`factoryAddresses: Record<number, Address>`). Fix `wallet_switchEthereumChain`
(`provider.ts:396`) to swap bundler and factory alongside the client — required even in Option B,
because the bootstrap at `:618` goes through the same code path.

*`wallet-web`* — `config.json` becomes a `chains: [...]` list, copying
`paymaster-admin`'s `Deployment` shape verbatim. `createWalletRuntime` becomes
`createWalletRuntimes(config)` returning a map, or a lazily-memoised `runtimeFor(chainId)`. Consent
screens display the chain name.

*`wallet-api`* — the bulk of the effort:
- `CHAIN_ID` / `RPC_URL` / `BUNDLER_URL` → a `CHAINS` JSON env (`[{ chainId, rpcUrl, bundlerUrl,
  entryPoint?, factory?, sponsorshipPaymaster? }]`), validated by zod exactly as `TENANTS_SEED` is,
  with the existing registry defaulting per entry. Keep the scalars as a deprecated single-entry
  shorthand so no deployment breaks.
- A `chains` service: `Map<chainId, { publicClient, bundlerService, paymasterReader,
  sponsorshipService }>`, built once at boot.
- Chain resolution per request. Two candidate mechanisms — **this is decision #2**:
  - **(i) In the body / params.** ERC-7677 already does this (`routes/paymaster.ts:174`) — just route
    on it instead of rejecting. For `POST /v1/userops`, add an explicit `chainId` field rather than
    inferring, so the server never guesses where an op is valid.
  - **(ii) In the path.** `/v1/chains/:chainId/userops`. More RESTful, self-documenting in OpenAPI,
    but a breaking URL change and it does not fit ERC-7677, which is a fixed JSON-RPC shape.
  → Recommend (i), with `chainId` required on new callers and defaulting to the single configured
  chain when only one is configured.
- Relay: hash against the **requested-and-validated** chain, never a body-supplied one that was not
  checked against the configured set (`userops.ts:136`).
- ERC-7677: route to the per-chain sponsorship service; keep the EntryPoint check per chain
  (`paymaster.ts:200`).
- Admin sponsorship routes: `chainId` becomes a required query/body parameter instead of
  `config.CHAIN_ID` (`admin-sponsorship.ts:38`). The tables are already keyed for it.
- One watcher per chain (`index.ts:48`), each with its own poll loop and lag metric.
- `/v1/version` gains `chains: number[]`, keeping `chainId` for compatibility. **OpenAPI drift check
  in CI will fail until regenerated** — expected, not a surprise.
- Metrics gain a `chain` label.

*Schema* — `ALTER TABLE userop_log ADD COLUMN chain_id bigint` (backfilled to the deployment's
current chain), plus the `credential_wallets` table **only if** §4.2 resolves the wrong way.

*Ops* — N bundlers, N funded executors, N paymaster deposits, per-chain deployer runs, extended
`determinism.yml`.

**Pros**
- One passkey, one identity, one session, N chains. The product story users actually want.
- One wallet-api, one Postgres, one wallet origin, one TLS host, one tenant onboarding.
- Fixes the mismatch class of bug outright: a dApp built for Base can no longer silently transact on
  Base Sepolia, because the handshake refuses.
- No provider state machine: the chain is immutable for the life of the provider instance, which is
  the simplest thing that can possibly work and the easiest to reason about under concurrency.
- Every wire change is additive; old dApps and old wallet origins keep working.

**Cons**
- wagmi's `useSwitchChain` / RainbowKit's chain picker will not work (they call
  `wallet_switchEthereumChain`, which stays unimplemented). A dApp that wants to switch must
  reconstruct the provider — which means reconnecting, which means a popup.
- `wallet-api` becomes meaningfully more complex; a single process now fails for N chains at once,
  so the blast-radius isolation of Option A is lost. Needs per-chain health reporting so one dead RPC
  does not report the whole service unhealthy.
- Does not address concurrent multi-chain use in one dApp session.

### 5.3 Option C — Native `wallet_switchEthereumChain` (Option B + mid-session switching)

Everything in B, plus the chain becomes mutable at runtime through the standard EIP-1193 method.

**Additional changes**
- Thin SDK: add `wallet_switchEthereumChain` (and optionally `wallet_addEthereumChain`) to
  `WALLET_METHODS` (`create-giano-wallet-provider.ts:28`) so it opens the popup transport; re-key the
  session cache on success (the key already contains the chain id, `:59`); swap the read-path
  `publicClient` for the new chain, which means the SDK needs the *list* of chains and transports,
  not one — so `CreateGianoWalletProviderParams` gains `chains: Chain[]` / `transports:
  Record<number, Transport>` while keeping `chain` as the initial selection.
- `wallet-core`: the `provider.ts:396` fix from B becomes load-bearing rather than defensive, and
  must also reset the cached static-call signature (`staticSignature`, `:192`) and re-derive the
  smart account against the new chain's factory. It already nulls `smartAccount` — good.
- `wallet-web`: `wallet_switchEthereumChain` is not in `CONSENT_METHODS` (`host.ts:6`) — **decide
  whether a chain switch needs user consent.** MetaMask asks. Given Giano's consent-gate posture, it
  probably should, at least the first time per origin per chain.
- Invalidate the sponsorship preflight and re-run it on switch (§4.5).
- `chainChanged` already flows; verify it survives the popup lifecycle (the popup is ephemeral —
  dismissed after each request — so a switch performed in one popup must persist to the next, i.e.
  the selected chain becomes part of the wallet origin's persisted session state, not just
  in-memory).

**Pros**
- Standards-compliant. wagmi, RainbowKit, viem and every dApp UI that already knows how to switch
  chains just work — no bespoke integration.
- The wagmi connector already implements `switchChain` (`connector.ts:65`), so this *closes an
  existing advertised-but-unimplemented capability* rather than adding surface.
- Best possible dApp-developer experience: Giano behaves like a wallet, not like a special case.

**Cons**
- Genuine state-machine risk. The chain is now mutable across an ephemeral-popup boundary, with a
  cached session, a cached static-call signature, an in-memory smart account and a sponsorship
  preflight all needing coherent invalidation. This is where the bugs will be.
- Needs a persisted "selected chain" on the wallet origin, which is new state with its own
  lifecycle.
- Still one chain at a time — a dApp cannot address two chains concurrently.

### 5.4 Option D — Explicit per-call chain (`provider.forChain(chainId)`)

Rather than (or in addition to) a mutable current chain, expose a chain-qualified provider or a
chain argument per call:

```ts
const provider = createGianoWalletProvider({ walletUrl, chains: [base, optimism] });
await provider.forChain(base.id).request({ method: 'eth_sendTransaction', params: [tx] });
await provider.forChain(optimism.id).request({ method: 'eth_sendTransaction', params: [tx] });
```

Implemented as a `chainId` field on the transport `rpc` payload (or a `giano_*` method family),
routed by the wallet origin to the right runtime. Sessions and accounts are shared; only the
execution target differs.

**Pros**
- The only option that supports **concurrent** multi-chain in one dApp session — the natural fit for
  a portfolio view, a cross-chain settlement flow, or "pay on whichever chain has balance".
- Stateless with respect to chain: no switch, no `chainChanged` race, no persisted selection. Far
  easier to reason about than C.
- Purely additive on top of B — same handshake work, same wallet-api work.

**Cons**
- Non-standard. viem/wagmi/RainbowKit cannot drive it; every consumer must be Giano-aware, which
  cuts against the thin-SDK-as-a-standard-provider positioning.
- Two ways to say the same thing if shipped alongside C, with the attendant "which one wins"
  questions.

**Verdict:** not a replacement for B or C. A good **additive** API for advanced dApps, once B exists.

### 5.5 Option E — Chain abstraction (named for completeness, out of scope)

Make the chain invisible: the user holds one balance, and the system routes/bridges (ERC-7683
intents, a cross-chain paymaster, a solver network). This is what the end state of "multi-chain UX"
looks like industry-wide, and it is the only design in which the user never picks a chain.

It is a different product, requiring bridge trust, solver liquidity and settlement risk management.
Worth naming so it is a conscious deferral rather than an oversight — and worth noting that **B is a
prerequisite for it either way**, since chain abstraction still needs the ability to execute on any
of N chains.

---

## 6. Comparison

| | **A** — stack per chain | **B** — chain per SDK instance ★ | **C** — native switch | **D** — per-call chain |
|---|---|---|---|---|
| One passkey across chains | ✗ | ✓ | ✓ | ✓ |
| One wallet address across chains | ✗ (separate origins) | ✓ (if §4.2 holds) | ✓ | ✓ |
| SDK selects the chain | via `walletUrl` | via `chain` at construction | via `chain` + `switchChain` | per call |
| Mid-session switching | ✗ | ✗ | ✓ | n/a (no state) |
| Concurrent multi-chain | ✗ | ✗ | ✗ | ✓ |
| wagmi / RainbowKit chain picker | ✗ | ✗ | ✓ | ✗ |
| Wire-protocol change | none | additive handshake field | additive + method routing | additive + rpc field |
| `wallet-api` change | none | substantial | substantial (same as B) | substantial (same as B) |
| Schema change | none | `userop_log.chain_id` | same as B | same as B |
| Infra cost per added chain | full stack | bundler + deposits | bundler + deposits | bundler + deposits |
| Blast-radius isolation | best | shared process | shared process | shared process |
| State-machine risk | none | low | **high** | low |
| Rough effort | ~0 (ops only) | **M–L** | L (B + delta) | S (on top of B) |

---

## 7. Recommendation

**Ship B. Then C. Add D if a consumer actually needs concurrency.**

Reasoning:

1. **B is the irreducible core.** C and D are both strictly B plus a delta. Every hour spent on B
   is spent regardless of the final destination, so B is the correct first milestone under any
   long-term choice. Nothing in B is wasted if you later decide C was unnecessary.
2. **B carries almost no risk in the layer that is hardest to debug.** With an immutable chain per
   provider instance, there is no cross-popup chain state, no invalidation ordering, no `chainChanged`
   race. The complexity that remains sits in `wallet-api`, which is server-side, testable, and where
   the chain is already a parameter almost everywhere.
3. **B closes a real correctness hole immediately** — the silent chain mismatch of §2.4 — which is a
   bug today, on one chain, with zero multi-chain ambition.
4. **C's cost is mostly UX design, not plumbing**, once B exists: consent-for-switch, persisted
   selection, preflight invalidation. Those are much easier to get right against a working
   multi-chain backend than at the same time as building one.
5. **A should be rejected as a design** (though it may describe the current testnet/mainnet split as
   an operational fact). Per-chain passkeys are not a wallet.

### Suggested phasing

**Phase 0 — Decide and enforce the address invariant (small, blocking)**
Resolve §4.2. If uniform-factory is the intent, enforce it: reject registry entries whose factory
differs, extend `determinism.yml` to assert CREATE2 addresses for every registered chain rather than
only Base, and document 381185's divergence. Nothing downstream can be designed until this is
settled, because it decides whether `credentials.wallet_address` survives.

**Phase 1 — Fix the latent switch bug (small, independently valuable)**
`provider.ts:396` — swap bundler and factory alongside the client, or throw explicitly when
`chains.length > 1` until it does. Add a `wallet-core` test asserting that a switch routes user
operations to the new chain's bundler. Ship this ahead of everything else; it is a correctness fix
that stands alone.

**Phase 2 — `wallet-api` multi-chain (large)**
`CHAINS` env, the per-chain services map, per-request chain resolution, per-chain watchers,
`chainId` on the admin sponsorship routes, `userop_log.chain_id`, per-chain health, `chain` metric
label, regenerated OpenAPI. Testable end-to-end against two anvil instances in the e2e stack before
any client work exists.

**Phase 3 — Handshake + `wallet-web` chain list (medium)**
Additive handshake fields, `config.json` as a `chains` list copying `paymaster-admin`'s shape,
`runtimeFor(chainId)`, chain on the consent screens, chain name (not bare id) in Settings.

**Phase 4 — Thin SDK (small)**
Declare the chain in the handshake, surface a typed `UnsupportedChainError`, document it in
`specs/DEVELOPER-GUIDE.md` §4 and `specs/INTEGRATION.md`. **This is the phase the original request
describes** — it is the smallest of the four.

**Phase 5 — E2E and ops**
Two-chain devnet in the e2e stack (regenerate `e2e/devnet/state.json` with the pinned anvil image —
a version mismatch takes the whole stack down misleadingly), a Playwright test that transacts on
both chains with one passkey, per-chain Helm values, per-chain deployer jobs, per-chain paymaster
funding runbook.

**Phase 6 (optional) — C, then D.**

---

## 8. Decisions needed before Phase 1

1. **Is the factory address guaranteed identical on every target chain?** (§4.2) Gates the schema
   and the entire product story. Why is 381185 different, and is that reproducible or historical?
2. **Chain in the request body or in the URL path?** (§5.2) Body is recommended — ERC-7677 forces it
   anyway — but the path is more RESTful and the OpenAPI contract is public.
3. **One wallet-api serving N chains, or one per chain sharing a database?** The latter keeps
   Option A's blast-radius isolation while keeping one passkey (one wallet origin fronting N
   backends via nginx path routing). It is a genuine middle road and cheaper than it sounds, given
   that the schema is already chain-keyed.
4. **Do you need mid-session switching (C), or is chain-at-construction (B) sufficient for the
   client use cases you actually have?** This determines whether Phase 6 is planned or speculative.
5. **Do any dApps need two chains concurrently (D)?**
6. **Per-chain tenant funding, or a pooled balance?** (§4.3) Per-chain is what the schema models and
   what the contracts enforce; pooled needs a bridge and is a separate product.
7. **Retire or redefine the chain id in the WebAuthn user handle?** (§4.6)
8. **Expose cross-chain owner sync** (`executeWithoutChainIdValidation`) as a first-class feature so
   adding a passkey propagates to every chain — and if so, what does the consent screen say?
9. **Does a chain switch require user consent?** (§5.3)
10. **How many chains, and which?** RIP-7212 availability differs per chain; without the precompile
    the FCL fallback costs materially more gas, which changes paymaster economics per chain.
    `pnpm run doctor chain` already checks this — run it per candidate chain before committing.

---

## Appendix — file-level change map

| Package / service | Files | Phase |
|---|---|---|
| `packages/contracts` | `addresses.ts` (registry entries), `.github/workflows/determinism.yml`, `scripts/doctor.ts` | 0 |
| `packages/wallet-core` | `provider.ts` (bundler/factory per chain, fix `wallet_switchEthereumChain`), `provider-injection/injection.ts` (user-id chain tag), `test/provider.test.ts` | 1, 3 |
| `packages/wallet-transport` | `protocol.ts` (handshake `chainId`, ack `supportedChainIds`), `client.ts`, `host.ts` | 3 |
| `packages/connector` | `thin/create-giano-wallet-provider.ts`, `connector.ts` (`switchChain` for C) | 4, 6 |
| `services/wallet-api` | `config.ts` (`CHAINS`), `app.ts` (services map), `index.ts` (N watchers), `routes/userops.ts`, `routes/paymaster.ts`, `routes/admin-sponsorship.ts`, `routes/health.ts`, `services/wallet-address.ts`, `db/schema.ts` + migration, `openapi/openapi.json` | 2 |
| `services/wallet-web` | `config.ts`, `wallet.ts`, `main.tsx`, `host.ts`, `views/ReviewTransaction.tsx`, `views/Settings.tsx`, `public/config.json`, `docker/config.json.template`, `docker/entrypoint.sh` | 3 |
| `services/paymaster-admin` | already multi-deployment — reference implementation, no change | — |
| `e2e` | `devnet/generate-state.mjs`, `devnet/state.json`, `dapp/main.ts`, `wallet-byo/src/config.ts`, `wallet-byo/serve.mjs`, `tests/` | 5 |
| `deploy` | `docker-compose.*.yml`, `helm/giano/values.yaml`, `templates/{wallet-api,wallet-web,bundler,deployer-job}.yaml` | 5 |
| `specs` | `DEVELOPER-GUIDE.md` (§4, §5), `INTEGRATION.md`, `PAYMASTER-SPECS.md`, `TRANSACTION-SUBMISSION-FLOW.md` | 4, 5 |
