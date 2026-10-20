# CreateX

[CreateX](https://github.com/pcaversaccio/createx) is the contract factory every canonical Giano
contract is deployed through, with CREATE3 (see `deploy/create3.ts`). It sits at
`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` on most EVM chains. Nothing here is deployed to a
public chain by this repo; the files exist for local chains and tests.

- `presigned-deployment.json`: CreateX's official keyless deployment transaction, the one that
  puts it at `0xba5Ed…ba5Ed` on every chain. Byte-identical to
  `scripts/presigned-createx-deployment-transactions/signed_serialised_transaction_gaslimit_3000000_.json`
  in the CreateX repository (checked Oct 2026). The deploy CLI's `install-createx` command sends it
  to anvil after funding its signer. On a public chain without CreateX, follow CreateX's own
  instructions instead.
- `CreateX.json`: CreateX's ABI and creation bytecode. The Foundry tests install it at its
  canonical address with `deployCodeTo` (`test/utils/CreateXFixture.sol`), and the deploy CLI takes
  its ABI from here.

Both were taken from `@nomicfoundation/ignition-core` 0.15, which vendors the same artifact.
CreateX is AGPL-3.0-only; these are its unmodified compiled artifacts, used only to deploy and test
against it.
