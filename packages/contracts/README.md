# @appliedblockchain/giano-contracts

Giano smart wallet contracts. The published npm package ships the wagmi-generated ABIs
(`generated.ts`), the per-chain deployed address registry (`addresses.ts`), the release code
fingerprints with `releaseOf` (`release-code.ts`) and the Solidity sources. Consumers never need
solc, Foundry or the submodules.

```ts
import { getGianoDeployment, releaseOf } from '@appliedblockchain/giano-contracts';

// Addresses are per chain: always ask the registry for the chain you are on.
const { factory, entryPoint } = getGianoDeployment(chainId);
// Which release the code at an address is, wherever it sits (undefined: not Giano's).
const release = releaseOf('GianoSmartWalletFactory', await client.getCode({ address: factory }));
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

## Addresses

Every Giano contract is deployed with **CREATE3 through [CreateX](https://github.com/pcaversaccio/createx)**
(`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`, on most EVM chains). Its address is a pure function
of two inputs, a **deployer** EOA and a **label** (`deploy/create3.ts`):

```
salt    = deployer (20 bytes) ‖ 0x00 ‖ keccak256(label)[0:11]
address = CreateX CREATE3(keccak256(bytes32(deployer) ‖ salt))
```

No bytecode, compiler setting or constructor argument enters an address, so a new release or
toolchain never moves one.

- **One canonical deployer per network class.** Every chain profile declares its class, `mainnet`
  or `testnet` (`deploy/chains/*.json`); local chains (31337/31338) are `local`. `deploy/config.ts`
  names one deployer per class (`DEPLOYERS`). Every chain of a class gets the same **deterministic
  addresses**, CREATE3 of the class deployer and the label, so all mainnets share one set and all
  testnets another. The two keys are independent, so a compromised testnet key never touches
  mainnet. A class whose deployer is `null` (not chosen yet) can be planned but never signed for.
- **The local deployer never changes.** Local chains impersonate a fixed placeholder (`0x…dEaD`)
  with no key, so the devnet, the e2e state and CI do not move when a real deployer is set.
- **Permissioned salt.** CreateX honours a salt whose first 20 bytes are the sender only from that
  sender. Nobody else can occupy a deterministic address, and a key other than the class deployer
  lands on its own addresses, never on the class's.
- **Per-chain overrides.** A profile can override single contracts (`addresses`: `walletImplementation`,
  `factory`, `paymasterImplementation`, `paymasterProxy`, `timelock`) when the contract already exists
  on that chain elsewhere. An override is verified and recorded, never deployed; contracts that
  depend on it use it. It is a **deviation**, and so is a run signed by another key: the deployment
  record keeps every deviation, and on a mainnet each one needs a typed confirmation.
- **Fixed labels.** `giano.wallet.impl`, `giano.factory`, `giano.paymaster.impl`,
  `giano.paymaster.proxy` (plus `giano.test.*` fixtures for local chains and testnets). A user's
  wallet address is the factory's CREATE2 of the implementation address and the owners, so it is
  the same on every chain one deployment serves; testnet and mainnet addresses differ.
- **Versioned labels for upgrades.** A label can be used once per chain. A newer implementation on
  a chain that already has one is deployed as an upgrade target, `giano.paymaster.impl@v2`, and the
  paymaster proxy (UUPS, and every user's account) moves to it.
- **Addresses do not prove code; fingerprints do.** Nothing compares an address with a constant.
  Each release publishes, per contract, a **fingerprint**: the hash of its runtime code with the
  immutables masked (`release-fingerprints.ts`, `pnpm gen:releases`). `releaseOf(contract, code)`
  says which release the code at any address is. The immutables are then checked against the chain's
  own addresses: the factory's `implementation()` is the registered wallet implementation, and the
  paymaster proxy's implementation slot holds paymaster release code. `deploy/immutable-checks.ts`
  lists every immutable and its check; a release that adds an unchecked one fails the tests.

`addresses.ts` (`getGianoDeployment(chainId)`) is the only source of a chain's addresses. It is
generated from the deployment records and `address-overrides.json`.

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

Adopt a public chain with the guided wizard, `pnpm contracts:deploy` from the repository root
([`deploy/contracts/README.md`](../../deploy/contracts/README.md)). It plans, shows every deviation,
asks for the confirmations, deploys, verifies and records. The low-level CLI (`deploy/cli.ts`)
underneath is idempotent: a contract already at its address is checked against the release
fingerprints and recorded, never redeployed. It cross-checks its address math against CreateX
before every deploy.

**The canonical deployer keys** are two development-team keys, mainnet and testnet, kept in
1Password and outside ABIP-8 scope: a deployer only places contracts at addresses, and holds no
role or funds on them once deployment ends ([`docs/key-ceremony.md`](../../docs/key-ceremony.md)
names the items). Load the key for the chain's class from its 1Password item into the deploying
shell's environment only; never write it to a file in the repository or to a client's configuration.

- **Verifying a chain needs no key.** Without `DEPLOYER_PRIVATE_KEY`, `core` and `testing` check that
  every contract is already in place with a release's code, record it, and send nothing. A missing
  contract fails the run.
- **Adopting a chain** needs the class's canonical deployer key. Each run prints, per contract, the
  expected address, the address it will use and the code there.
- **Mainnet deviations are gated.** On a mainnet, an override, another signing key or a contract
  recorded away from its deterministic address is a deviation. The wizard prints a warning that names
  each one and requires typing `deviate <profile>`; non-interactive runs refuse, and `core` needs
  `--allow-deviation`. Testnet deviations are reported and recorded, not gated.
- **Local chains** (31337/31338) impersonate the local deployer with `--impersonate` and need no key.

```bash
pnpm deploy:cli addresses                                          # deterministic addresses per class
pnpm deploy:cli core --rpc <url> --role-admin <timelock>           # no key: verify only
pnpm deploy:cli core --rpc <url> --network testnet --role-admin <timelock>   # a chain without a profile
pnpm deploy:cli core --rpc <local url> --role-admin <0x…> --impersonate      # local chains
pnpm deploy:cli p256 --rpc <url>                                   # P-256 verifier, where RIP-7212 is missing
# With the class's deployer key in DEPLOYER_PRIVATE_KEY (this shell only):
#   core --rpc <url> --chain <profile> --role-admin <timelock> [--allow-deviation]
#   testing --rpc <url> --holder <0x…> --owner <0x…>               # never on 8453/84532/11155111
#   upgrade --rpc <url> --contract paymaster --release v2
```

The CLI takes a chain's class and overrides from `--chain <profile>`, else from the committed profile
with the chain's id, else from `--network mainnet|testnet` (no overrides).

`core` deploys the wallet implementation, the factory, the paymaster implementation and the
paymaster proxy. The proxy is a stock `ERC1967Proxy` with an empty payload that CreateX initialises
in the same transaction (`deployCreate3AndInit`), so no unconfigured proxy is ever exposed and
nothing operator-specific reaches its init code. Paymaster options: `--entry-point`,
`--default-fee-wei`, `--post-op-gas-allowance`, `--penalty-bps`.

`upgrade` deploys the release's implementation under its versioned label. For the paymaster it
then prints the `upgradeToAndCall` calldata for whoever holds `UPGRADER_ROLE` (a timelock in
production), or sends it with `--execute` from `UPGRADER_PRIVATE_KEY`. Upgrades go through UUPS: a
replacement proxy would strand its tenant balances and funding address. No initializer runs.

Every run writes `deployments/<chainId>.json`: the network class, the signer and, per contract, its
address, expected address, whether it is deterministic, release, code hash, fingerprint and
transaction, plus every deviation. **Commit it** for every chain except the local ones;
`pnpm gen:addresses` builds `addresses.ts` from these records and fails if a recorded fingerprint
matches no release of that contract. Per-chain extras the CLI does not deploy (e.g. a non-default
EntryPoint) go in `address-overrides.json`.

The `giano-contracts-deployer` image (`Dockerfile.deployer`) runs `core` (and `testing` with
`DEPLOY_TESTING=true`) from environment variables, with `NETWORK` naming the chain's class; see
`scripts/deployer-entrypoint.mjs`. Without `DEPLOYER_PRIVATE_KEY` it only verifies, which is how the
Helm pre-install Job runs in a client's cluster. Never give it a canonical deployer key there.

### Local chains

```bash
pnpm local:node        # anvil
pnpm local:deploy      # CreateX, EntryPoint, P-256 verifier, every core contract and fixture
```

`local:deploy` impersonates the fixed local deployer, so it needs no key. On a local chain the CLI
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
solc `0.8.28`, EVM `cancun` (EntryPoint v0.9 requires MCOPY and transient storage; deploy only on
chains implementing Cancun opcodes), optimizer runs `200`, `viaIR`, and the remappings in `remappings.txt`
(auto-detection is off: solc records remappings in the metadata hash).

Generated, committed files, so a fresh clone builds the TypeScript surface with no solc, no
submodules and no network:

| File | Source | Regenerate |
| --- | --- | --- |
| `generated.ts` | wagmi's `foundry` plugin over a build of `src/` | `pnpm gen:abis` |
| `release-fingerprints.ts` | `releases/<vN>/standard-input.json`, compiled with plain solc | `pnpm gen:releases` |
| `addresses.ts` | `deployments/<chainId>.json` + `address-overrides.json` | `pnpm gen:addresses` |

CI regenerates all three and fails on drift.

```bash
pnpm build:ts    # tsdown only — what prepublishOnly runs; needs no solc
pnpm build       # gen:abis + gen:addresses + tsdown (needs forge and the submodules)
pnpm test        # forge test (needs the submodules: pnpm git:init at the repo root)
pnpm storage:check
```

## Guided contract deployment

Run `pnpm contracts:deploy` from the repository root. Public chain configuration persists in
`deploy/chains/*.json`; use `--chain <profile>` or `--config <file>` to choose a deployment.
The same profile drives `contracts:funding`, `contracts:provision`, `contracts:sponsorship` and
`contracts:doctor`. See [the deployment and address-cutover runbook](../../deploy/contracts/README.md)
for prerequisites, saved operator choices, read-only plans, provisioning, verification and recovery.
