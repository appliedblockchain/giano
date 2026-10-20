---
'@appliedblockchain/giano-contracts': major
---

Canonical contracts are now deployed with CREATE3 through CreateX, from committed releases, by a
dedicated canonical deployer. Every canonical address is a function of that deployer and a fixed
label only, so no future compiler, toolchain or contract release moves it again.

Breaking:

- **New canonical addresses.** `CANONICAL_FACTORY`, `CANONICAL_IMPLEMENTATION`,
  `CANONICAL_SPONSORSHIP_PAYMASTER` and `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION` all change.
  They still derive from a placeholder deployer and change once more when the real one is set.
- **The address registry is empty** (`gianoAddresses`, `getGianoDeployment`) until the chains are
  redeployed under the new scheme; the old Base, Base Sepolia and Sepolia deployments are dropped.
- Removed: `CANONICAL_PAYMASTER_DEPLOYER`, `gianoPaymasterDeployerAbi` and `create2Abi`. CreateX's
  `deployCreate3AndInit` deploys and initialises the paymaster proxy atomically, so
  `GianoPaymasterDeployer` is gone.
- `PrivateERC20` and `PermissivePaymaster` (test fixtures) take their holder and owner as
  constructor arguments.

Added: `CANONICAL_DEPLOYER`, `CANONICAL_LABELS`, `CANONICAL_CODE` (the runtime codehash each
release leaves at each canonical address) and `canonicalCodeAt(address, codehash)`. An address no
longer proves which code sits there; check the code too.
