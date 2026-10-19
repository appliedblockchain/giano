# @appliedblockchain/giano-contracts

Giano smart wallet contracts. The published npm package ships the wagmi-generated ABIs
(`generated.ts`), the per-chain deployed address registry (`addresses.ts`) and the Solidity
sources — consumers never need solc, Hardhat or the Foundry submodules.

## Paymaster signer verification and upgrades

Paymaster sponsorship authorisations support ECDSA signatures only; ERC-1271 contract signers
are not supported. Validation recovers the signing address and checks it against the signer
allowlist without inspecting or calling the signer. Safe-mode ERC-4337 bundlers reject
`EXTCODESIZE` against an account with no code. Invalid signatures, including estimation stubs,
return signature-validation failure.

This change adds no storage fields. Existing ECDSA signers need no re-registration after an
upgrade. Replace any existing ERC-1271 sponsorship signer with an ECDSA key through
`SIGNER_ADMIN_ROLE`. Upgrade the existing proxy through UUPS; deploying a replacement proxy
would strand its tenant balances and funding address.

To upgrade dev on Base Sepolia, use the current PR's compiled contracts and an account holding
`UPGRADER_ROLE` on the existing proxy. Set `BASE_SEPOLIA_RPC_URL` and `BASE_PRIVATE_KEY` in your
deployment environment, then create a parameters file (for example `upgrade-dev.json`):

```json
{
  "UpgradePaymaster": {
    "proxyAddress": "<existing dev paymaster proxy address>"
  }
}
```

Run from `packages/contracts`:

```bash
pnpm hh:compile
pnpm hh:upgrade:paymaster --network base-sepolia \
  --parameters upgrade-dev.json --deployment-id dev-paymaster-ecdsa-upgrade
```

The module deploys only the implementation and calls `upgradeToAndCall(implementation, "0x")`
on the supplied proxy. It checks the proxy's EntryPoint before deploying and requires an
`Upgraded` event. No initializer runs and the proxy address stays unchanged.
The EntryPoint check verifies the interface; the upgrade preserves the proxy's configured
EntryPoint, including a custom deployment. Confirm that the supplied proxy belongs to the
intended dev environment before running the command.
Use a new deployment ID for a later implementation upgrade; reuse the same ID to resume an
interrupted deployment.
If a Safe or timelock holds `UPGRADER_ROLE`, it must execute the upgrade transaction; this module
requires the configured transaction sender to hold that role directly.

```ts
import { gianoSmartWalletAbi, gianoSmartWalletFactoryAbi, getGianoDeployment, ENTRYPOINT_V07_ADDRESS } from '@appliedblockchain/giano-contracts';

const { factory, entryPoint } = getGianoDeployment(84532); // Base Sepolia
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

## Canonical build & deploy toolchain

**Hardhat Ignition is the only supported deploy path.** Canonical compiler settings (also used
by CI's determinism check):

| Setting | Value |
| --- | --- |
| solc | `0.8.28` |
| optimizer | enabled, `runs: 200` |
| viaIR | `true` |
| deploy strategy | Ignition `create2`, salt `0xAB…AB` |

Because every production deployment uses CREATE2, **any change to compiler settings or bytecode
changes the deployed addresses**. Foundry (`forge test`) is for tests only — the old
`[profile.deploy]` in `foundry.toml` diverged from these settings and was removed.

### Generated, committed artifacts

Two files are generated but committed, so a fresh clone can build the TypeScript surface with no
solc, no submodules and no network:

- `generated.ts` — wagmi-cli output over the Hardhat artifacts (`pnpm hh:compile && pnpm hh:wagmi`)
- `addresses.ts` — address registry derived from the git-tracked `ignition/deployments/chain-*/deployed_addresses.json` journals merged with `address-overrides.json` (`pnpm gen:addresses`)

CI regenerates both and fails on drift.

### Common tasks

```bash
pnpm build:ts        # tsup only — what prepublishOnly runs; needs no solc
pnpm build           # full: compile + wagmi + addresses + tsup
pnpm gen:addresses   # regenerate addresses.ts from ignition journals
forge test           # Foundry unit tests (requires git submodules)
pnpm hh:deploy --network base-sepolia   # Ignition CREATE2 deploy
```

### Adding a chain

1. Deploy with Ignition (`pnpm hh:deploy --network <net>`; testing extras via `hh:deploy:testing`).
2. Commit the new `ignition/deployments/chain-<id>/` journal (deployed_addresses.json included).
3. Add per-chain overrides (e.g. a non-default EntryPoint) to `address-overrides.json` if needed.
4. `pnpm gen:addresses` and commit the regenerated `addresses.ts`.

Note: `sdr-testnet` (chain 381185) is only registered in `hardhat.config.ts` when
`SDR_TESTNET_RPC_URL` is set (see `.env.example`).
