# Production keys and the key ceremony (ABIP-8)

Every private key that can move mainnet value or hold a privileged role in a live Giano deployment
is produced by the [ABIP-8 Key Generation Ceremony](https://app.notion.com/p/applied-blockchain/ABIP-8-Key-Generation-Ceremony-399b61bd7d52811b8811f762cbe1bde0).
The ceremony is run by **DevOps only**: the development team never has access to these keys, and
neither do clients. This page is the Giano-specific part: which keys exist, where each one lives,
and what to do with it. For how a ceremony itself is run (the clean VM, `multichain-keygen --rng
openssl`, quiet mode, the Notion record template), read ABIP-8. This page does not restate it.

The repository-level contract is the `production-key-ceremony` capability in OpenSpec.

## Inventory

A key is **in scope** if it can move mainnet value, sign production transactions, or hold a
privileged role on a deployed contract or service. If the classification is unclear, treat it as in
scope. Whoever adds a key to a service or tool adds it here in the same PR.

| Key | What it signs, or the role it holds | ABIP-8 scope | Where it lives | Consumed by |
|-----|-------------------------------------|--------------|----------------|-------------|
| **Canonical deployer** (`CANONICAL_DEPLOYER`, `DEPLOYER_PRIVATE_KEY` for the deploy CLI) | Owns every canonical CREATE3 salt: the only key that can put Giano's contracts at their canonical addresses, on **any** chain. Permanent. | **In scope on every chain, testnets included.** One key adopts every chain, so a testnet adoption uses the production key. | DevOps secret store (a KMS/HSM key, or the `Giano prd` 1Password vault) | the deploy CLI, run by DevOps only. Never a service, never a client deployment. The Helm deployer Job runs **without** it and only verifies. |
| **Sponsorship signer** (`SPONSORSHIP_SIGNER_KEY_REF`) | Signs paymaster sponsorship data, i.e. authorises spending the operator's gas. Holds no funds. | Production: in scope. Testnet `dev`: out of scope. | Production: inside the HSM/KMS (`SPONSORSHIP_SIGNER_KIND=hsm`), generated there or imported there by DevOps from a ceremony, never exported. wallet-api refuses `local` in the `production` class. `dev`: 1Password `secrets-dev` field `sponsorship-signer-key`, mirrored to Secrets Manager (`SPONSORSHIP_SIGNER_KIND=local`, class `testnet`). | wallet-api |
| **Bundler executor** (`BUNDLER_EXECUTOR_PRIVATE_KEYS`) | Submits and **pays gas for** every `handleOps` transaction; funded on each chain. | Production: in scope. `dev` (Base Sepolia, Ethereum Sepolia): out of scope. | 1Password `secrets-<env>` field `alto-executor-key` (Alto-era name), mirrored to Secrets Manager; `prd` uses the `Giano prd` vault | giano-bundler |
| **Paymaster `ROLE_ADMIN`**, and the TimelockController's **proposer/executor** keys | Grants every other paymaster role (`SIGNER_ADMIN`, `FEE_ADMIN`, `FEE_COLLECTOR`, `STAKE_ADMIN`, `TENANT_ADMIN`, `PARAM_ADMIN`, `PAUSER`, `UPGRADER`). In production it is a TimelockController, whose proposer and executor keys are the real signers. | Production: in scope (every key that can propose or execute). `dev`: a developer-held EOA on testnets, out of scope. | Production: DevOps secret store, one ceremony per key | the timelock; `provision:paymaster` and `upgrade --execute` (`UPGRADER_PRIVATE_KEY`) only on a devnet or a first-run testnet |
| **Paymaster operator** (`DEPLOYER_PRIVATE_KEY` in `provision:paymaster` and the paymaster-sdk CLI) | Stakes the paymaster and funds tenants' sponsorship balances. The same variable name as the canonical deployer's, but a different account. | Production: in scope (moves mainnet value). Testnets and devnets: out of scope. | Production: DevOps secret store | `provision:paymaster`, the paymaster-sdk CLI |
| Platform-admin API keys (`ADMIN_API_KEYS`) | Bearer tokens for the wallet-api admin routes. Not private keys. | Out of scope for ABIP-8; still secrets, kept in the secret store. | 1Password → Secrets Manager | wallet-api |
| Anvil dev keys ([`E2E-DEV-KEYS.md`](E2E-DEV-KEYS.md)) | Local chains 31337/31338 and CI only; recoverable from anvil's public mnemonic. | Out of scope: local and CI keys. They must never be used on a public chain. | committed / anvil defaults | e2e, devnet |

Giano has no production environment yet (`infra/versions.json` `prd` is empty), and
`CANONICAL_DEPLOYER` is still the placeholder `0x…dEaD`. No in-scope key exists today. Every key in
scope above is created by a ceremony when it is first needed.

## Runbook

For every in-scope key, DevOps:

1. **Run the ceremony** as ABIP-8 describes, on a clean VM, with `multichain-keygen generate --type evm
   --rng openssl --quiet`. Do not use HD or mnemonic derivation, unless an approved exception is
   recorded.
2. **Pipe the key straight into its store**, without displaying it or writing it to disk:

   | Key | Store | Item / field |
   |-----|-------|--------------|
   | Canonical deployer | KMS/HSM key, or the `Giano prd` vault | `canonical-deployer` (one, for every chain) |
   | Sponsorship signer | the production HSM/KMS key named by `SPONSORSHIP_SIGNER_KEY_REF` | — |
   | Bundler executor | `Giano prd` vault, note `secrets-prd` | `alto-executor-key` (bump its `version`; `infra/iac/asm.tf` mirrors it) |
   | Timelock proposer / executor, paymaster operator | `Giano prd` vault | one item per key |

3. **Record the ceremony** on a Notion page that uses the ABIP-8 template. Until Giano has its own
   teamspace, file it under the `Giano` coordination page ([`AGENTS.md`](../AGENTS.md) → Notion). The
   record holds the **public address**, never the private key.
4. **Publish the address** to the service owner, the tech lead in `AGENTS.md`, so the key in use can
   be checked against the ceremony record. Per key:
   - **Canonical deployer:** the address replaces the placeholder in
     `packages/contracts/deploy/config.ts`, following the
     [switch procedure](../packages/contracts/README.md#canonical-addresses). That moves every canonical
     address, so the PR links the ceremony record. Then DevOps adopt each chain with the key (`deploy:cli
     core`). Anyone can verify the result afterwards with the same command and no key.
   - **Sponsorship signer:** the address is authorised on the paymaster through the timelock
     (`SIGNER_ADMIN_ROLE`).
   - **Bundler executor and operator:** fund the address on each chain, and watch its balance
     (`giano.chain.balance`).
5. **Rotate** a key that was generated outside a ceremony, or that the development team has seen. Do it
   with a new ceremony, then move every on-chain role to the new address, then destroy the old key
   (ABIP-8 "Migration / Adoption").

## What the repository does to keep it this way

- `deploy:cli core` / `testing` without `DEPLOYER_PRIVATE_KEY` only verify. Every contract must
  already be in place with a release's code, and a missing one fails with "adoption is a DevOps
  operation". The `giano-contracts-deployer` image and the Helm pre-install Job run that way. The
  chart's `values.yaml` says never to put the key in `secrets.existingSecret`.
- The developer-facing docs mark `DEPLOYER_PRIVATE_KEY=…` commands as local/testnet operator commands,
  or as DevOps-only: `packages/contracts/README.md`, `specs/INFRASTRUCTURE.md` §13.1,
  `specs/INTEGRATION.md`, `specs/DEVELOPER-GUIDE.md` and `specs/CHAIN-ADOPTION.md`. On local chains,
  `--impersonate` (or `DEPLOYER_IMPERSONATE=true`) needs no key at all.
- wallet-api refuses an in-process sponsorship signer in the `production` deployment class.
- **Superseded:** `deploy/sepolia/` keeps `CANONICAL_DEPLOYER_PRIVATE_KEY` in a local `deploy/.env`. That
  flow may only be run by DevOps, from the secret store. #160 replaces it with `deploy/contracts/`,
  and that replacement must follow the same rule.
- The development team has no read access to the `Giano prd` 1Password vault. That is enforced in
  1Password, not here, and is confirmed by DevOps.
