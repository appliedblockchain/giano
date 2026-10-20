# Deployment records

One `<chainId>.json` per chain, written by the deploy CLI (`pnpm deploy:cli`, see `deploy/cli.ts`):
every canonical contract's address, label, release, runtime codehash and deploying transaction, plus
the upgrade targets deployed later under versioned labels.

Commit the record for every chain except the local ones (31337 and 31338, gitignored).
`pnpm gen:addresses` builds `addresses.ts` from these files and fails if any address or codehash is
not canonical (`canonical.ts`).

None exist yet: the canonical deployer in `deploy/config.ts` is still a placeholder. See "Deploying
to a chain" in `../README.md`.
