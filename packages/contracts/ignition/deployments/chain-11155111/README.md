# chain-11155111 — reconstructed, not written by Ignition

This directory holds a hand-written `deployed_addresses.json` and nothing else. The Ethereum
Sepolia deployment was made outside this repo and its journal was never committed to any branch,
so the tooling that reads `deployed_addresses.json` — `scripts/generate-addresses.ts` and the
determinism workflow — had no entry for the chain and `gianoAddresses[11155111]` did not exist.
Every consumer that defaults `factoryAddress` from the registry failed for the chain, which in
wallet-kit fails the whole wallet config rather than the one chain.

**This is a placeholder with a deadline.** Recover the real journal from the deploying machine, or
redeploy the frozen canonical build to a chain that does not yet carry it, and replace this
directory with what Ignition writes. Until then:

- `hardhat ignition status chain-11155111` does not work here — there is no journal to read.
- `hardhat ignition deploy --network sepolia` treats the chain as undeployed. It will not produce a
  divergent deployment: the salt is fixed and CreateX reverts with `FailedContractCreation` because
  the addresses are already occupied.

## Provenance of the two addresses

Both were created through CreateX (`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`) from
`0xFebBB1e5b6D66E6281d0d4d4816f76B69365a09d` on 2026-09-11:

| Future | Address | Block | Transaction |
|---|---|---|---|
| `GianoAccountFactory#GianoSmartWallet` | `0x15cC758f7D3188c2361f6141CEaa9Ab2792bea56` | 11683085 | `0xd53e4c04c894310dd09f8f959f29eda0fb2f0a35df123c3567142893e0332d8e` |
| `GianoAccountFactory#GianoSmartWalletFactory` | `0x26dCd29390eba3B22BcCbd2143989E5994Ac7050` | 11683090 | `0x7a2666d46ee45e94e06b7e0215336059f0bc8f2a50334b157bf13f1eae64fbda` |

Both match the frozen constants in `canonical.ts`, their runtime bytecode is byte-identical to Base
Sepolia's, and `pnpm run doctor chain --rpc <sepolia> --chain-id 11155111` passes every critical
check — including the MC-22 cross-check, where `factory.getAddress` for a probe key returns
`0x42033071b2faa2213236B6e95B0426f0cc154D19` on both this chain and Base Sepolia.
