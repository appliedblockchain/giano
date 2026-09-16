---
'@appliedblockchain/giano-contracts': patch
---

Register Ethereum Sepolia (11155111) in `gianoAddresses`. The canonical factory and wallet
implementation are deployed there at their frozen addresses with runtime bytecode identical to Base
Sepolia's, but the deployment was made outside this repo and its Ignition journal was never
committed, so the address generator had nothing to read and consumers that default `factoryAddress`
from the registry — wallet-kit and wallet-api both do — could not resolve the chain. A
`deployed_addresses.json` reconstructed from the on-chain deployment stands in until the journal is
recovered; `ignition/deployments/chain-11155111/README.md` records its provenance and what it does
not cover.
