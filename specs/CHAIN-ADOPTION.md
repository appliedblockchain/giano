# Chain adoption checklist

Chains are adopted on client demand rather than from a fixed list, so adoption is a routine
operation and must be turnkey rather than tribal knowledge. This checklist is the deliverable
MC-146 requires, and **passing it is a gate, not an advisory** (MC-147): a chain that has not
passed it must not be added to any deployment's served list.

The property everything rests on: for a given passkey, the smart account address is identical on
every chain a deployment serves (MC-16). That holds only when the factory and implementation sit
at the **canonical addresses** — `CANONICAL_FACTORY` and `CANONICAL_IMPLEMENTATION`, exported by
`@appliedblockchain/giano-contracts` (`canonical.ts`) — **and run canonical code** there
(`CANONICAL_CODE`, the codehash each release leaves at each address).

Canonical addresses are CREATE3 through CreateX: a function of the canonical deployer EOA and a
fixed label only (`packages/contracts/README.md`, "Canonical addresses"). The salts are
permissioned, so **only the canonical deployer can adopt a chain** — step 4 needs its key. Because
an address no longer commits to bytecode, code is checked separately (steps 5 and 8).

## The checklist

```
1.  CreateX present at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed?
      Every canonical contract is deployed through it (MC-25). Most EVM chains have it; where
      absent, deploy it with its own keyless presigned transaction (github.com/pcaversaccio/
      createx) — that is what puts it at the same address everywhere. The deploy CLI refuses
      to run without it.

2.  EntryPoint v0.7 at 0x0000000071727De22E5E9d8BAf0edAc6f37da032?
      The account implementation HARDCODES this address, so against a different EntryPoint
      the implementation is different code: it would still land at the canonical address, but
      as code no release puts there (MC-141). Public chains almost always have it; a PRIVATE
      chain will not — deploy it there BEFORE any Giano contract (`deploy:cli
      install-entrypoint` is the local recipe).

3.  RIP-7212 P-256 precompile present?
      Informational; drives fee tuning. Where absent, deploy the FreshCryptoLib verifier
      (`pnpm --filter @appliedblockchain/giano-contracts deploy:cli p256 --rpc <url>`) —
      giano-doctor treats missing P-256 verification as CRITICAL.

4.  Deploy the canonical contracts — with the canonical deployer's key, which only DevOps hold.
      The key is generated in an ABIP-8 ceremony and never reaches the development team
      (docs/key-ceremony.md); this step is a DevOps request, run with the key from the secret store:
        pnpm --filter @appliedblockchain/giano-contracts \
          deploy:cli core --rpc <url> --role-admin <timelock>
      Anyone can re-run the same command WITHOUT a key afterwards: it verifies every contract and its
      code and sends nothing.
      From a committed release, never a fresh build (MC-26): the release's creation code is
      what every chain gets. Idempotent; commit the record it writes
      (packages/contracts/deployments/<chainId>.json).

5.  Assert the addresses and the code are canonical.
      pnpm --filter @appliedblockchain/giano-contracts gen:addresses fails on a non-canonical
      address or codehash (MC-99). Non-canonical code at a canonical address means the wrong
      EntryPoint or a contract that did not come from a release — do NOT register the chain;
      find the cause (step 2 is the usual culprit).

6.  Fund the bundler's executor account on this chain.
      Each chain needs the submission account funded on it (MC-98); the executor fronts gas
      for every bundle. One key serves every chain (nonces are per chain), so this is the
      same address funded once more, not a new key.

7.  Deploy, stake and fund the paymaster; register tenants on this chain.
      The proxy comes with step 4; then provision:paymaster. Sponsorship is per chain: every tenant
      that sponsors here funds a balance HERE, and configures its rules HERE — nothing is
      inherited from another chain (MC-67).

8.  giano-doctor chain --rpc <url> --chain-id <id> …  → must be green.
      The same checks the wallet-api runs at boot: endpoint identity, EntryPoint, canonical
      factory + implementation (address and code), P-256, paymaster stake/deposit (MC-100).

9.  Add the entry to GIANO_CHAINS; roll the deployment.
      The backend chain document (packages/contracts/chains.ts) is shared by wallet-api, the
      bundler and paymaster-admin, so one entry adds the chain to all three: the running
      giano-bundler serves it at POST /<chainId>, and wallet-api derives that URL from
      BUNDLER_BASE_URL — no new bundler service.
      Adding a chain is a DEPLOYMENT action, never an admin API call (MC-91). The
      wallet-api re-verifies every configured chain at boot and refuses to start on any
      structural failure (MC-20, MC-49); a merely unreachable chain starts 'unavailable'
      and is retried (MC-54).

10. Verify end to end.
      GET /v1/version lists the chain as ready; a sponsored transaction succeeds on it.
```

Steps 2 and 5 are the ones that fail *silently* if skipped — a deployment against a
non-canonical EntryPoint produces perfectly working contracts at the canonical addresses, running
an implementation bound to an EntryPoint the bundlers do not use. The address checks all pass; only
the code check (step 5, and the wallet-api's `code-not-canonical` boot failure) catches it.

## The single-chain (on-premises) profile

An on-premises deployment sets `CHAIN_ID`, `RPC_URL` and `BUNDLER_URL` and is done (MC-88). It
never supplies `GIANO_CHAINS`, never sees a chain picker, never supplies a `chainId` on a backend
request, and its operator needs no knowledge of the multi-chain shape (MC-90). Single-chain is
the degenerate case of N, not a separate build or mode (MC-86, MC-87).

The things it **does** need, and which are easy to miss: **EntryPoint v0.7 and CreateX at their
canonical addresses** (steps 1 and 2). A private chain will have neither; without EntryPoint the
implementation is not canonical code, and without CreateX nothing can be deployed at all.

## Per-chain operating costs (recurring)

Serving a chain costs, per chain and forever (MC-75, MC-98):

- the bundler executor account funded on that chain, monitored
  (`giano_bundler_executor_balance_wei`, labelled by chain);
- a staked, funded paymaster deposit, monitored (low-balance alerting);
- an RPC endpoint, and the bundler's path for that chain, monitored (`giano_chain_available`,
  `giano_bundler_chain_ready`, per-chain watcher lag metrics);
- for every sponsoring tenant, a funded per-chain balance — tenants fund per chain, and
  balances never pool across chains (D7).
