# Chain adoption checklist

Chains are adopted on client demand rather than from a fixed list, so adoption is a routine
operation and must be turnkey rather than tribal knowledge. This checklist is the deliverable
MC-146 requires, and **passing it is a gate, not an advisory** (MC-147): a chain that has not
passed it must not be added to any deployment's served list.

The property everything rests on: for a given passkey, the smart account address is identical on
every chain a deployment serves (MC-16). That holds only when the factory and implementation sit
at the **canonical addresses** — the frozen constants `CANONICAL_FACTORY` and
`CANONICAL_IMPLEMENTATION` exported by `@appliedblockchain/giano-contracts` (`canonical.ts`) —
which in turn requires every step below.

## The checklist

```
1.  Deterministic deployer present?
      The Arachnid CREATE2 proxy must sit at 0x4e59b44847b379578588920ca78fbf26c0b4956c.
      → giano-doctor chain reports it; if absent, deploy it first (MC-25).

2.  EntryPoint v0.7 at 0x0000000071727De22E5E9d8BAf0edAc6f37da032?
      The account implementation HARDCODES this address, so a chain carrying a different
      EntryPoint produces different account bytecode and different addresses for everything
      downstream (MC-141). Public chains almost always have it; a PRIVATE chain will not —
      deploy it there BEFORE any Giano contract (see `e2e/devnet/setup-entrypoint.mjs` for
      the local recipe).

3.  RIP-7212 P-256 precompile present?
      Informational; drives fee tuning. Where absent, deploy the FreshCryptoLib verifier
      (packages/contracts/scripts/p256_deploy.ts) — giano-doctor treats missing P-256
      verification as CRITICAL.

4.  Deploy the canonical contracts.
      pnpm --filter @appliedblockchain/giano-contracts hh:deploy --network <target>
      (Hardhat Ignition, create2 strategy, fixed salt — from the FROZEN build: same solc
      version, optimizer runs, viaIR and EVM target as hardhat.config.ts pins, MC-26.)

5.  Assert the produced addresses equal CANONICAL_FACTORY / CANONICAL_IMPLEMENTATION.
      pnpm --filter @appliedblockchain/giano-contracts gen:addresses fails on divergence
      (MC-99). A divergent result means the wrong sources or the wrong EntryPoint — do NOT
      register the chain; find the cause (step 1 or 2 is the usual culprit).

6.  Fund the bundler's executor account.
      Each chain needs its own funded submission account (MC-98); the executor fronts gas
      for every bundle.

7.  Deploy, stake and fund the paymaster; register tenants on this chain.
      hh:deploy:paymaster + provision:paymaster. Sponsorship is per chain: every tenant
      that sponsors here funds a balance HERE, and configures its rules HERE — nothing is
      inherited from another chain (MC-67).

8.  giano-doctor chain --rpc <url> --chain-id <id> …  → must be green.
      The same checks the wallet-api runs at boot: endpoint identity, EntryPoint, canonical
      factory + implementation, P-256, paymaster stake/deposit (MC-100).

9.  Add the descriptor to GIANO_CHAINS; roll the deployment.
      Adding a chain is a DEPLOYMENT action, never an admin API call (MC-91). The
      wallet-api re-verifies every configured chain at boot and refuses to start on any
      structural failure (MC-20, MC-49); a merely unreachable chain starts 'unavailable'
      and is retried (MC-54).

10. Verify end to end.
      GET /v1/version lists the chain as ready; a sponsored transaction succeeds on it.
```

Steps 1, 2 and 5 are the ones that fail *silently* if skipped — a deployment against a
non-canonical EntryPoint produces perfectly working contracts at the wrong addresses, and the
mistake surfaces only when a user's funds arrive at an address their passkey does not control on
that chain.

## The single-chain (on-premises) profile

An on-premises deployment sets `CHAIN_ID`, `RPC_URL` and `BUNDLER_URL` and is done (MC-88). It
never supplies `GIANO_CHAINS`, never sees a chain picker, never supplies a `chainId` on a backend
request, and its operator needs no knowledge of the multi-chain shape (MC-90). Single-chain is
the degenerate case of N, not a separate build or mode (MC-86, MC-87).

The one thing it **does** need, and which is easy to miss: **EntryPoint v0.7 at its canonical
address** (step 2). A private chain will not have it, and without it every Giano address in that
deployment shifts and nothing lines up.

## Per-chain operating costs (recurring)

Serving a chain costs, per chain and forever (MC-75, MC-98):

- a funded bundler executor account, monitored;
- a staked, funded paymaster deposit, monitored (low-balance alerting);
- an RPC endpoint and a bundler endpoint, monitored (`giano_chain_available`,
  per-chain watcher lag metrics);
- for every sponsoring tenant, a funded per-chain balance — tenants fund per chain, and
  balances never pool across chains (D7).
