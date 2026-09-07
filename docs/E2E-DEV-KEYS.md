# Development & testing key census — the e2e / example stack

Every private key, account and fixed address the local demo stack uses, in one place.

**None of these is a secret.** Both private keys below are the first two accounts of Foundry's
public, deterministic anvil mnemonic (`test test test … junk`) — they are hard-coded in anvil, in
this repository, and in thousands of others. They exist so that a devnet is reproducible, and their
value is that everyone already knows them.

> ## Never use any key in this document on a network that holds real value
>
> Anything sent to these addresses on a public chain is spendable by anyone. There are bots that
> sweep them within seconds of a balance appearing.

Scope: `deploy/docker-compose.e2e.yml`, `deploy/docker-compose.dev.yml`, `e2e/`, and the dev
tooling in `packages/`. Real deployments are covered under [Where real keys live](#where-real-keys-live).

---

## 1. Private keys — the complete set

Only **two** private keys appear anywhere in the dev/test surface.

| # | Address | Private key | Used as |
| --- | --- | --- | --- |
| anvil 0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` | contract deployer · paymaster `ROLE_ADMIN` · alto **executor** · default key for the SDK CLI & demo |
| anvil 1 | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` | `0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d` | **sponsorship signer** (signs the paymaster's EIP-712 authorisations) · alto **utility** key |

Verified with `cast wallet address --private-key <key>`.

### Where each is referenced

| Key | File |
| --- | --- |
| anvil 0 | `deploy/docker-compose.e2e.yml:57` (`--executor-private-keys`) |
| | `deploy/docker-compose.dev.yml:36` (default for `ALTO_EXECUTOR_PRIVATE_KEY`) |
| | `e2e/devnet/generate-state.mjs:58` (`deployer`) |
| | `packages/contracts/scripts/provision-paymaster.ts:32` (`ANVIL_KEY`) |
| | `packages/paymaster-sdk/cli/index.ts:41`, `packages/paymaster-sdk/demo/cli.ts:30` |
| | `services/bundler/entrypoint.sh:10`, `services/wallet-api/test/paymaster-chain.test.ts:76` |
| anvil 1 | `deploy/docker-compose.e2e.yml:58` (`--utility-private-key`), `:115` (`SPONSORSHIP_SIGNER_KEY_REF`) |
| | `deploy/docker-compose.dev.yml:37` (default for `ALTO_UTILITY_PRIVATE_KEY`) |
| | `e2e/devnet/generate-state.mjs:60`, `e2e/devnet/addresses.json:9` (`sponsorshipSignerKey`) |
| | `packages/wallet-core/test/account.test.ts:15` |

`SPONSORSHIP_SIGNER_KEY_REF` is named "…KEY_REF" because in production it is a *reference* to a key
in a KMS. On the devnet the reference is the raw key itself.

---

## 2. Accounts used by address only

These hold funds or receive them, but their private keys appear **nowhere** in the repository. They
are still anvil defaults, so the keys are recoverable from the public mnemonic — listed here so the
census is complete, not because the stack needs them.

| # | Address | Used as |
| --- | --- | --- |
| anvil 2 | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | tenant `stock`'s withdrawal address |
| anvil 3 | `0x90F79bf6EB2c4f870365E785982E1f101E93b906` | tenant `byo`'s withdrawal address |

A tenant's withdrawal address is the **only** account that can move that tenant's balance — no
paymaster role can, including all of them at once. On the devnet these are deliberately different
from the deployer so that separation is exercised rather than assumed.

---

## 3. Contract addresses — devnet (chain 31337)

Deterministic: baked into `e2e/devnet/state.json` and mirrored in `e2e/devnet/addresses.json`.

| Contract | Address |
| --- | --- |
| EntryPoint v0.7 (canonical, all chains) | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| `GianoSmartWalletFactory` | `0x26dCd29390eba3B22BcCbd2143989E5994Ac7050` |
| `GianoSmartWallet` implementation | `0x15cC758f7D3188c2361f6141CEaa9Ab2792bea56` |
| **`GianoPaymaster` (proxy)** | `0x15a2075f2407427C5dd0BDe9d1966c48BD70E2f2` |
| `GianoPaymaster` implementation | `0x25fd38704b938F656cCB4806e17A491d56b41ba8` |
| `PermissivePaymaster` (test only) | `0xCbc040482c1dd07D533800874DC37De7b18c8092` |
| Test ERC-20 | `0x9967bDf929856643e92EF65eefdE1fF8250774D8` |

The **proxy** address is what tenants fund and what the admin console and `USEROP_ALLOWED_PAYMASTERS`
point at. The implementation address changes on every upgrade; the proxy must not.

### Well-known addresses the stack probes

| Address | What |
| --- | --- |
| `0x4e59b44847b379578588920ca78fbf26c0b4956c` | Arachnid deterministic-deployment (CREATE2) factory |
| `0x0000000000000000000000000000000000000100` | RIP-7212 P-256 precompile (if the chain has one) |
| `0xc2b78104907F722DABAc4C69f826a522B2754De4` | daimo p256-verifier — the in-contract fallback |
| `0x000000000000000000000000000000000000dEaD` | burn address; the sample dApp's *deliberately* unlisted contract, used to demonstrate a sponsorship refusal |

---

## 4. Paymaster role holders (devnet)

On the devnet every role is held by **anvil 0**. This is a development convenience and collapses the
separation the contract exists to enforce — `provision-paymaster.ts` says so loudly when you pass
`--grant-all-to`.

| Role | Devnet holder | Production |
| --- | --- | --- |
| `ROLE_ADMIN` | anvil 0 | timelock |
| `UPGRADER_ROLE` | anvil 0 | timelock |
| `SIGNER_ADMIN_ROLE`, `FEE_ADMIN_ROLE`, `FEE_COLLECTOR_ROLE`, `STAKE_ADMIN_ROLE`, `TENANT_ADMIN_ROLE`, `PARAM_ADMIN_ROLE`, `PAUSER_ROLE` | anvil 0 | separate holders |
| `DEFAULT_ADMIN_ROLE` | **nobody — by design** | nobody |

`DEFAULT_ADMIN_ROLE` being empty is asserted by the contract tests, by `giano-doctor`, and by the
admin console's health check. A holder would be a superuser by another name.

---

## 5. Tenants (devnet)

| Slug | Tenant id (UUID) | Withdrawal address | Funded |
| --- | --- | --- | --- |
| `stock` | `11111111-1111-4111-8111-111111111111` | anvil 2 · `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | 50 ETH |
| `byo` | `22222222-2222-4222-8222-222222222222` | anvil 3 · `0x90F79bf6EB2c4f870365E785982E1f101E93b906` | 50 ETH |

The UUID *is* the on-chain id: it is stored as `bytes16`, so `11111111-1111-4111-8111-111111111111`
is `0x11111111111141118111111111111111` on-chain. There is no second identifier to keep in step.

---

## 6. Non-key credentials

Not private keys, but they authenticate and belong in a census.

| Credential | Value | Scope |
| --- | --- | --- |
| `stock` admin API key | `e2e-admin-key-stock` | wallet-api `/v1/admin/*` for tenant `stock` |
| `byo` admin API key | `e2e-admin-key-byo00` | same, tenant `byo` |
| dev-stack admin key | `dev-admin-key-local` | `deploy/docker-compose.dev.yml` single dev tenant |
| Postgres | user `giano`, db `giano` | container-local only, not published beyond `5432` |

Passkeys are **not** in this list: the e2e tests create them at runtime with Chrome's CDP virtual
authenticator, so no credential is ever stored in the repository. There is no passkey to leak.

---

## 7. Origins and ports

| Origin | Port | Served by |
| --- | --- | --- |
| http://app.localhost | 4400 | sample dApp / dApp fixture |
| http://app-byo.localhost | 4401 | same fixture, tenant `byo` |
| http://wallet.localhost | 8081 | `wallet-web` container |
| http://wallet-byo.localhost | 8082 | BYO wallet fixture |
| http://paymaster.localhost | 8083 | paymaster admin console |
| http://api.localhost | 8080 | `wallet-api` |
| http://rpc.localhost | 8545 | anvil |
| http://bundler.localhost | 4337 | alto |

`e2e/origins.mjs` is the single source of truth. `wallet.localhost` and `wallet-byo.localhost` double
as WebAuthn **RP IDs**, so renaming either means updating `TENANTS_SEED` and `GIANO_RP_ID` to match.

---

## Where real keys live

Deliberately **not** in this document, and not in the repository.

- `deploy/.env` — gitignored. Holds the real `DEPLOYER_PRIVATE_KEY`, `ALTO_EXECUTOR_PRIVATE_KEY`,
  `ALTO_UTILITY_PRIVATE_KEY` and `ADMIN_API_KEY` for a testnet deployment. **Never commit it, and
  never copy its values into a document — this one included.**
- `deploy/sepolia.env.example` — the template. Variable names only, no values. That is the file to
  read to learn what a real deployment needs.
- Production role holders are timelocks and the sponsorship signer lives in a KMS, so there is no
  raw production private key for anyone to write down.

If a key in this document ever appears in a `deploy/.env` for a network with real value, treat that
deployment as compromised from the moment it was funded.

---

## Reproducing this

```sh
# every key/address the compose stacks use
grep -nE "PRIVATE_KEY|0x[a-fA-F0-9]{40}|0x[a-fA-F0-9]{64}" deploy/docker-compose.e2e.yml

# the devnet's deterministic addresses
cat e2e/devnet/addresses.json

# confirm a key derives to the address claimed here
cast wallet address --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
#   → 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# audit a live deployment's roles, signers and tenants
pnpm paymaster roles   --rpc http://rpc.localhost
pnpm paymaster signers --rpc http://rpc.localhost
pnpm paymaster status  --rpc http://rpc.localhost
```
