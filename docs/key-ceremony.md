# Production keys and the key ceremony (ABIP-8)

Every private key that can move mainnet value or hold a privileged role in a live Giano deployment
is produced by the [ABIP-8 Key Generation Ceremony](https://app.notion.com/p/applied-blockchain/ABIP-8-Key-Generation-Ceremony-399b61bd7d52811b8811f762cbe1bde0).
The ceremony is run by **DevOps only**: the development team never has access to these keys, and
neither do clients. The canonical deployer keys are the exception. They only pay deployment gas and
hold no authority, so the development team creates them and keeps them in 1Password
([below](#canonical-deployers)). This page is the Giano-specific part: which keys exist, where each one lives,
and what to do with it. For how a ceremony itself is run (the clean VM, `multichain-keygen --rng
openssl`, quiet mode, the Notion record template), read ABIP-8. This page does not restate it.

The repository-level contract is the `production-key-ceremony` capability in OpenSpec.

## Inventory

A key is **in scope** if it can move mainnet value, sign production transactions, or hold a
privileged role on a deployed contract or service. If the classification is unclear, treat it as in
scope. Whoever adds a key to a service or tool adds it here in the same PR.

| Key | What it signs, or the role it holds | ABIP-8 scope | Where it lives | Consumed by |
|-----|-------------------------------------|--------------|----------------|-------------|
| **Canonical deployers**, one for **mainnet** and one for **testnet** (`DEPLOYER_PRIVATE_KEY` / `CANONICAL_DEPLOYER_PRIVATE_KEY` for the deploy tooling) | Own the canonical CREATE3 salts of their network class, so they decide *where* Giano's contracts land on a chain of that class. They pay the deployment gas and nothing else: no role, no funds and no authority on any deployed contract (`ROLE_ADMIN` is a separate key). | **Out of scope.** They are not hot keys: they are never deployed to a live environment and are used only from the deploying shell for a one-off adoption. They hold only a gas float. | 1Password, provided by the development team. Two independent keys, never one key or two derived from a common seed. | the deploy tooling, run by the development team. Never a service, never a client deployment. The Helm deployer Job runs **without** them and only verifies. |
| **Sponsorship signer** (`SPONSORSHIP_SIGNER_KEY_REF`) | Signs paymaster sponsorship data, i.e. authorises spending the operator's gas. Holds no funds. | Production: in scope. Testnet `dev`: out of scope. | Production: inside the HSM/KMS (`SPONSORSHIP_SIGNER_KIND=hsm`), generated there or imported there by DevOps from a ceremony, never exported. wallet-api refuses `local` in the `production` class. `dev`: 1Password `secrets-dev` field `sponsorship-signer-key`, mirrored to Secrets Manager (`SPONSORSHIP_SIGNER_KIND=local`, class `testnet`). | wallet-api |
| **Bundler executor** (`BUNDLER_EXECUTOR_PRIVATE_KEYS`) | Submits and **pays gas for** every `handleOps` transaction; funded on each chain. | Production: in scope. `dev` (Base Sepolia, Ethereum Sepolia): out of scope. | 1Password `secrets-<env>` field `alto-executor-key` (Alto-era name), mirrored to Secrets Manager; `prd` uses the `Giano prd` vault | giano-bundler |
| **Paymaster `ROLE_ADMIN`**, and the TimelockController's **proposer/executor** keys | Grants every other paymaster role (`SIGNER_ADMIN`, `FEE_ADMIN`, `FEE_COLLECTOR`, `STAKE_ADMIN`, `TENANT_ADMIN`, `PARAM_ADMIN`, `PAUSER`, `UPGRADER`). In production it is a TimelockController, whose proposer and executor keys are the real signers. | Production: in scope (every key that can propose or execute). `dev`: a developer-held EOA on testnets, out of scope. | Production: DevOps secret store, one ceremony per key | the timelock; `provision:paymaster` and `upgrade --execute` (`UPGRADER_PRIVATE_KEY`) only on a devnet or a first-run testnet |
| **Paymaster operator** (`DEPLOYER_PRIVATE_KEY` in `provision:paymaster` and the paymaster-sdk CLI) | Stakes the paymaster and funds tenants' sponsorship balances. The same variable name as the canonical deployer's, but a different account. | Production: in scope (moves mainnet value). Testnets and devnets: out of scope. | Production: DevOps secret store | `provision:paymaster`, the paymaster-sdk CLI |
| Anvil dev keys ([`E2E-DEV-KEYS.md`](E2E-DEV-KEYS.md)) | Local chains 31337/31338 and CI only; recoverable from anvil's public mnemonic. | Out of scope: local and CI keys. They must never be used on a public chain. | committed / anvil defaults | e2e, devnet |

Giano has no production environment yet (`infra/versions.json` `prd` is empty), and neither canonical
deployer is configured yet (`DEPLOYERS.mainnet` and `DEPLOYERS.testnet` are `null` in
`packages/contracts/deploy/config.ts`). No in-scope key exists today. Every key in
scope above is created by a ceremony when it is first needed.

### Canonical deployers

The canonical deployers do not go through the ceremony. They are created by the development team and
stored in 1Password:

- **Two keys.** One owns the mainnet salts and one the testnet salts, so a testnet adoption never
  touches the mainnet key. They are independent random keys, never one key or two derived from a
  common seed, and `deploy/config.ts` refuses equal addresses. Local chains use a fixed placeholder
  (`0x…dEaD`, impersonated) that has no key at all.

  | Deployer | `deploy/config.ts` | 1Password item |
  |----------|--------------------|----------------|
  | Mainnet canonical deployer | `DEPLOYERS.mainnet` | not created yet; the PR that sets the address names it here |
  | Testnet canonical deployer | `DEPLOYERS.testnet` | not created yet; the PR that sets the address names it here |

- **Use.** Load the key for the chain's class from its 1Password item into the environment of the
  deploying shell only, for the run (`CANONICAL_DEPLOYER_PRIVATE_KEY` for the guided wizard,
  `DEPLOYER_PRIVATE_KEY` for `deploy:cli`). Never write it to a file in the repository, a dotenv
  file, a client's configuration or a deployment record; the deploy tooling never prints or records
  it. A testnet run takes the testnet key, never the mainnet one.
- **Mainnet guard.** A mainnet deployment signed by any key other than the mainnet canonical deployer
  lands on that key's own addresses. The wizard treats it as a deviation: it warns, names every
  affected contract and requires a typed confirmation, and the deployment record keeps it.
- **Funding.** Keep only enough gas on the key for the adoption at hand. Top it up per run rather than
  holding a balance.
- **Address.** Setting a deployer address in `deploy/config.ts` sets the deterministic addresses of
  that class; no local-chain or devnet address moves. The PR names the 1Password item that holds the
  matching key, and no ceremony record is needed.
- **Loss or leak.** A leaked key cannot touch any deployed contract. It can, however, occupy the
  canonical addresses of its class on chains not yet adopted. If that happens, create a new key and
  update `deploy/config.ts`. Chains adopted afterwards then get the new key's addresses, or a per-chain
  override.

## Runbook

For every in-scope key, DevOps:

1. **Run the ceremony** as ABIP-8 describes, on a clean VM, with `multichain-keygen generate --type evm
   --rng openssl --quiet`. Do not use HD or mnemonic derivation, unless an approved exception is
   recorded.
2. **Pipe the key straight into its store**, without displaying it or writing it to disk:

   | Key | Store | Item / field |
   |-----|-------|--------------|
   | Sponsorship signer | the production HSM/KMS key named by `SPONSORSHIP_SIGNER_KEY_REF` | — |
   | Bundler executor | `Giano prd` vault, note `secrets-prd` | `alto-executor-key` (bump its `version`; `infra/iac/asm.tf` mirrors it) |
   | Timelock proposer / executor, paymaster operator | `Giano prd` vault | one item per key |

3. **Record the ceremony** on a Notion page that uses the ABIP-8 template. Until Giano has its own
   teamspace, file it under the `Giano` coordination page ([`AGENTS.md`](../AGENTS.md) → Notion). The
   record holds the **public address**, never the private key.
4. **Publish the address** to the service owner, the tech lead in `AGENTS.md`, so the key in use can
   be checked against the ceremony record. Per key:
   - **Sponsorship signer:** the address is authorised on the paymaster through the timelock
     (`SIGNER_ADMIN_ROLE`).
   - **Bundler executor and operator:** fund the address on each chain, and watch its balance
     (`giano.chain.balance`).
5. **Rotate** a key that was generated outside a ceremony, or that the development team has seen. Do it
   with a new ceremony, then move every on-chain role to the new address, then destroy the old key
   (ABIP-8 "Migration / Adoption").

## What the repository does to keep it this way

- `deploy:cli core` / `testing` without `DEPLOYER_PRIVATE_KEY` only verify. Every contract must
  already be in place with a release's code, and a missing one fails: adopting a chain needs the
  class's canonical deployer, which the development team operates. The `giano-contracts-deployer`
  image and the Helm pre-install Job run that way, and never ask for the key.
  The Helm Job loads no Secret, and the chart's `values.yaml` says never to give it the key.
- The developer-facing docs mark `DEPLOYER_PRIVATE_KEY=…` commands as local/testnet operator commands,
  or as canonical-deployer runs that take the key from 1Password: `packages/contracts/README.md`,
  `specs/INFRASTRUCTURE.md` §13.1, `specs/INTEGRATION.md`, `specs/DEVELOPER-GUIDE.md` and
  `specs/CHAIN-ADOPTION.md`. On local chains, `--impersonate` (or `DEPLOYER_IMPERSONATE=true`) needs no
  key at all.
- wallet-api refuses an in-process sponsorship signer in the `production` deployment class.
- The development team has no read access to the `Giano prd` 1Password vault. That is enforced in
  1Password, not here, and is confirmed by DevOps.
