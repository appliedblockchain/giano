# Deployment records

One `<chainId>.json` per chain, written by the deploy CLI (`pnpm deploy:cli`, see `deploy/cli.ts`)
and the guided wizard: the chain's network class, the address that signed (null until a signing run
deploys something), and per contract its address, label, expected address, whether it is
deterministic, release, runtime codehash, release fingerprint and deploying transaction. It also
lists the upgrade targets deployed later under versioned labels, the timelock, and every deviation
from the deterministic addresses.

Commit the record for every chain except the local ones (31337, 31338 and 31339, gitignored).
`pnpm gen:addresses` builds `addresses.ts` from these files and fails if a recorded fingerprint
matches no release of that contract, or if the recorded release is not one of the releases with that
fingerprint. Addresses are not compared with fixed constants: a chain's contracts may sit at
overridden or recorded addresses, as long as they run release code.

`84532.json` (Base Sepolia) and `11155111.json` (Ethereum Sepolia) hold release v3, deployed by the
testnet canonical deployer on 2026-11-17 (`deploy/contracts/TESTNET-ROLLOUT.md`, steps 5–7). The
mainnet deployer is not chosen yet (`null`), so nothing can be signed for a mainnet. See "Deploying
to a chain" in `../README.md`.
