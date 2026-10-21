# @appliedblockchain/giano-contracts

Giano smart wallet contracts. The published npm package ships the wagmi-generated ABIs
(`generated.ts`), the per-chain deployed address registry (`addresses.ts`), the canonical addresses
and code (`canonical.ts`) and the Solidity sources. Consumers never need solc, Foundry or the
submodules.

```ts
import { gianoSmartWalletAbi, gianoSmartWalletFactoryAbi, getGianoDeployment, CANONICAL_FACTORY } from '@appliedblockchain/giano-contracts';

const { factory, entryPoint } = getGianoDeployment(chainId);
```

## Installing from GitHub Packages

The package is published to GitHub Packages under the `@appliedblockchain` scope:

```ini
# .npmrc — project-level, in the consuming app
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

> **Scope caveat:** routing the whole `@appliedblockchain` scope to GitHub Packages means the
> same project can no longer fetch the *public* `@appliedblockchain/silentdatarollup-*` packages
> from npmjs. Those are devDependencies of this repo only and are never required by consumers of
> the published Giano packages. If you do need both in one project, override per-install with
> `npm_config_@appliedblockchain:registry`.

## Canonical addresses

Every canonical contract is deployed with **CREATE3 through [CreateX](https://github.com/pcaversaccio/createx)**
(`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`, on most EVM chains). Its address is a pure function
of two inputs, the **canonical deployer** EOA and a **label** (`deploy/create3.ts`):

```
salt    = deployer (20 bytes) ‖ 0x00 ‖ keccak256(label)[0:11]
address = CreateX CREATE3(keccak256(bytes32(deployer) ‖ salt))
```

No bytecode, compiler setting or constructor argument enters an address. A compiler upgrade, a
toolchain change or a new contract release never moves one, and a chain adopted in five years gets
the same addresses as every chain today.

- **Permissioned salt.** CreateX honours a salt whose first 20 bytes are the sender only from that
  sender. Nobody else can occupy a canonical address on a chain we have not adopted yet. The flip
  side is that **only the canonical deployer can adopt a chain.** Its key is permanent: keep it in a
  KMS or HSM, use it for nothing else, and never lose it.
- **Fixed labels.** Everything an address is derived from, or that people send funds to, has a
  fixed label: `giano.wallet.impl`, `giano.factory`, `giano.paymaster.impl`,
  `giano.paymaster.proxy` (plus `giano.test.*` fixtures for local chains and testnets). A user's
  wallet address is the factory's CREATE2 of the implementation address and the owners, so it is
  the same on every chain, forever.
- **Versioned labels for upgrades.** A label can be used once per chain. A newer implementation on
  a chain that already has one is deployed as an upgrade target, `giano.paymaster.impl@v2`, and the
  paymaster proxy (UUPS, and every user's account) moves to it. A chain adopted later gets the then
  current release directly under the fixed labels.
- **Addresses do not prove code.** Different chains may hold different releases at one address.
  `canonical.ts` therefore also lists `CANONICAL_CODE`: the runtime codehash each release leaves at
  each canonical address. `giano-doctor chain` and the wallet-api's boot-time chain check verify
  both the address and the code.

The deployer and the labels live in `deploy/config.ts`. **`CANONICAL_DEPLOYER` is currently a
placeholder** (`0x…dEaD`); local chains impersonate it, and the deploy CLI refuses any other chain
while it is set. Switching to the real deployer:

1. Set its address in `deploy/config.ts`.
2. `pnpm gen:canonical` (needs `anvil`), then regenerate the devnet state:
   `pnpm -F @appliedblockchain/giano-e2e devnet:generate:all`.
3. Replace the old devnet addresses wherever they are written out (`grep` for the old factory
   address: the e2e and infrastructure compose files, `services/paymaster-admin/public/config.json`,
   `services/custom-example/.env.development`, the spa-parity fixtures, `docs/E2E-DEV-KEYS.md`).

## Releases

The deploy CLI deploys **releases**, never a fresh build. `releases/<vN>/` holds:

- `release.json`: the creation code of every deployable contract and the compiler identity.
- `standard-input.json`: the exact solc standard-JSON input (sources, settings, remappings).

```bash
pnpm release:status    # which contracts differ from the latest release
pnpm release:cut v2    # build with Foundry and freeze releases/v2 (refuses an existing version)
pnpm release:verify    # recompile every release with plain solc and check it reproduces
```

Releases are immutable. A contract change is a new release; deploying it to an existing chain is an
upgrade (versioned label), deploying it to a new chain uses the fixed labels. `release:verify`
makes a release independent of Foundry: anyone can rebuild it from its input with the solc it names.

## Deploying

The deploy CLI (`deploy/cli.ts`) is idempotent: a contract already at its address is checked and
recorded, never redeployed. It cross-checks its address math against CreateX before every deploy,
and refuses to sign with any key but the canonical deployer's.

```bash
pnpm deploy:cli addresses                                          # the canonical addresses
DEPLOYER_PRIVATE_KEY=… pnpm deploy:cli core --rpc <url> --role-admin <timelock>
DEPLOYER_PRIVATE_KEY=… pnpm deploy:cli testing --rpc <url> --holder <0x…> --owner <0x…>  # never on 8453/84532/11155111
DEPLOYER_PRIVATE_KEY=… pnpm deploy:cli upgrade --rpc <url> --contract paymaster --release v2
pnpm deploy:cli p256 --rpc <url>                                   # P-256 verifier, where RIP-7212 is missing
```

`core` deploys the wallet implementation, the factory, the paymaster implementation and the
paymaster proxy. The proxy is a stock `ERC1967Proxy` with an empty payload that CreateX initialises
in the same transaction (`deployCreate3AndInit`), so no unconfigured proxy is ever exposed and
nothing operator-specific reaches its init code. Paymaster options: `--entry-point`,
`--default-fee-wei`, `--post-op-gas-allowance`, `--penalty-bps`.

`upgrade` deploys the release's implementation under its versioned label. For the paymaster it
then prints the `upgradeToAndCall` calldata for whoever holds `UPGRADER_ROLE` (a timelock in
production), or sends it with `--execute` from `UPGRADER_PRIVATE_KEY`. Upgrades go through UUPS: a
replacement proxy would strand its tenant balances and funding address. No initializer runs.

Every run writes `deployments/<chainId>.json`: addresses, labels, releases, codehashes and
transactions. **Commit it** for every chain except the local ones; `pnpm gen:addresses` builds
`addresses.ts` from these records and fails if any address or codehash is not canonical. Per-chain
extras the CLI does not deploy (e.g. a non-default EntryPoint) go in `address-overrides.json`.

The `giano-contracts-deployer` image (`Dockerfile.deployer`) runs `core` (and `testing` with
`DEPLOY_TESTING=true`) from environment variables; see `scripts/deployer-entrypoint.sh`.

### Local chains

```bash
pnpm local:node        # anvil
pnpm local:deploy      # CreateX, EntryPoint, P-256 verifier, every canonical contract and fixture
```

`local:deploy` impersonates the canonical deployer, so it needs no key. On a local chain the CLI
also takes `--release dev` (the working tree, unreleased), `--impersonate`, `install-createx` and
`install-entrypoint`. The e2e devnet state is built the same way (`e2e/devnet/generate-state.mjs`).

## Paymaster signer verification and upgrades

Paymaster sponsorship authorisations support ECDSA signatures only; ERC-1271 contract signers
are not supported. Validation recovers the signing address and checks it against the signer
allowlist without inspecting or calling the signer. Safe-mode ERC-4337 bundlers reject
`EXTCODESIZE` against an account with no code. Invalid signatures, including estimation stubs,
return signature-validation failure.

## Toolchain

Foundry is the only Solidity toolchain. `foundry.toml` pins everything that reaches the bytecode:
solc `0.8.28`, EVM `paris` (no `PUSH0`, `MCOPY` or transient storage, so one release deploys on
every chain we may adopt), optimizer runs `200`, `viaIR`, and the remappings in `remappings.txt`
(auto-detection is off: solc records remappings in the metadata hash).

Generated, committed files, so a fresh clone builds the TypeScript surface with no solc, no
submodules and no network:

| File | Source | Regenerate |
| --- | --- | --- |
| `generated.ts` | wagmi's `foundry` plugin over a build of `src/` | `pnpm gen:abis` |
| `canonical.ts` | `deploy/config.ts` + `releases/`, deployed to a throwaway anvil | `pnpm gen:canonical` |
| `addresses.ts` | `deployments/<chainId>.json` + `address-overrides.json` | `pnpm gen:addresses` |

CI regenerates all three and fails on drift.

```bash
pnpm build:ts    # tsdown only — what prepublishOnly runs; needs no solc
pnpm build       # gen:abis + gen:addresses + tsdown (needs forge and the submodules)
pnpm test        # forge test (needs the submodules: pnpm git:init at the repo root)
pnpm storage:check
```
