# Chain adoption checklist

Chains are adopted on client demand rather than from a fixed list, so adoption is a routine
operation and must be turnkey rather than tribal knowledge. This checklist is the deliverable
MC-146 requires, and **passing it is a gate, not an advisory** (MC-147): a chain that has not
passed it must not be added to any deployment's served list.

The property everything rests on: for a given passkey, the smart account address is identical on
every chain a deployment serves (MC-16). That holds only when every served chain's factory derives
the same wallets, which is true when each chain's factory and implementation sit at their class's
**deterministic addresses** **and run release code** there. The addresses are per chain, from the
registry (`getGianoDeployment(chainId)` in `@appliedblockchain/giano-contracts`); the code is
checked by **release fingerprint** (`releaseOf`, the runtime code hash with immutables masked),
wherever it sits.

Deterministic addresses are CREATE3 through CreateX: a function of the network class's canonical
deployer EOA and a fixed label only (`packages/contracts/README.md`). There is one canonical
deployer per class, `mainnet` and `testnet` (`DEPLOYERS` in `deploy/config.ts`), so every chain of
a class shares one set of addresses and testnet and mainnet addresses differ. The salts are
permissioned, so **only the class's canonical deployer can adopt a chain at the deterministic
addresses** — step 4 needs its key. Any other placement (an override, another signing key) is a
deviation: recorded always, and on a mainnet only with an explicit confirmation. Because an
address does not commit to bytecode, code is checked separately (steps 5 and 8).

EntryPoint v0.9 requires Cancun EVM opcodes (including `MCOPY`, `TLOAD`, and `TSTORE`) and
an EIP-1559 `basefee`. Confirm RPC support for `eth_call` state overrides and gas estimation.
See [E1 upgrade implications and chain evidence](../docs/ENTRYPOINT-V09-UPGRADE.md).

## The checklist

```
1.  CreateX present at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed?
      Every canonical contract is deployed through it (MC-25). Most EVM chains have it; where
      absent, deploy it with its own keyless presigned transaction (github.com/pcaversaccio/
      createx) — that is what puts it at the same address everywhere. The deploy CLI refuses
      to run without it.

2.  EntryPoint v0.9 at 0x433709009B8330FDa32311DF1C2AFA402eD8D009?
      The account implementation HARDCODES this address, so against a different EntryPoint
      the implementation is different code: it would still land at the deterministic address, but
      as code that matches no release fingerprint (MC-141). Verify runtime code with giano-doctor, including its chain-dependent EIP-712 cache. A PRIVATE
      chain will not — deploy it there BEFORE any Giano contract (`deploy:cli
      install-entrypoint` is the local recipe).

3.  RIP-7212 P-256 precompile present?
      Informational; drives fee tuning. Where absent, deploy the FreshCryptoLib verifier
      (`pnpm --filter @appliedblockchain/giano-contracts deploy:cli p256 --rpc <url>`) —
      giano-doctor treats missing P-256 verification as CRITICAL.

4.  Deploy the contracts — with the canonical deployer key of the chain's class (the profile's
      "network"). Both keys are development-team keys kept in 1Password, outside ABIP-8 scope
      (docs/key-ceremony.md names the items). Load the key for the class from its 1Password item
      into the deploying shell's environment only (DEPLOYER_PRIVATE_KEY for deploy:cli,
      CANONICAL_DEPLOYER_PRIVATE_KEY for the wizard) — never into a file in the repository, a dotenv
      or a client's configuration; a testnet adoption uses the testnet key, never the mainnet one:
        pnpm --filter @appliedblockchain/giano-contracts \
          deploy:cli core --rpc <url> --chain <profile> --role-admin <timelock>
      On a mainnet profile any deviation (an override, another signing key, a contract recorded
      away from its deterministic address) is always refused: the command has no prompt, and only
      the guided wizard (pnpm contracts:deploy), which requires typing `deviate <profile>`, can
      confirm one. Testnet deviations are shown and recorded. --role-admin must not be a deployer
      key (the signer or a class deployer).
      Anyone can re-run the same command WITHOUT a key afterwards: it verifies every contract and its
      code and sends nothing.
      From a committed release, never a fresh build (MC-26): the release's creation code is
      what every chain gets. Idempotent; commit the record it writes
      (packages/contracts/deployments/<chainId>.json).

5.  Assert the code is release code.
      pnpm --filter @appliedblockchain/giano-contracts gen:addresses fails on a recorded code
      fingerprint that matches no release of that contract (MC-99). Code that is no release's
      means the wrong EntryPoint or a contract that did not come from a release — do NOT
      register the chain; find the cause (step 2 is the usual culprit). Review every deviation
      the record lists.
      A match does not prove the EntryPoint: an older release (EntryPoint v0.7) also has a
      committed fingerprint. Step 8 checks that implementation.entryPoint() is the configured
      EntryPoint.

6.  Fund the bundler's executor account on this chain.
      Each chain needs the submission account funded on it (MC-98); the executor fronts gas
      for every bundle. One key serves every chain (nonces are per chain), so this is the
      same address funded once more, not a new key.

7.  Deploy, stake and fund the paymaster; register tenants on this chain.
      The proxy comes with step 4; then provision:paymaster. Sponsorship is per chain: every tenant
      that sponsors here funds a balance HERE, and configures its rules HERE — nothing is
      inherited from another chain (MC-67).

8.  giano-doctor chain --rpc <url> --chain-id <id> …  → must be green.
      The same checks the wallet-api runs at boot: endpoint identity, EntryPoint, factory +
      implementation (release code, the factory clones the chain's implementation, and
      implementation.entryPoint() is the configured EntryPoint), P-256,
      paymaster stake/deposit (MC-100). It also reports whether each address is deterministic
      for the class; with --profile it fails on an undeclared mainnet deviation.

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
non-canonical EntryPoint produces perfectly working contracts at the deterministic addresses,
running an implementation bound to an EntryPoint the bundlers do not use. The address checks all
pass; only the code checks catch it: step 5 (`code-not-release` at wallet-api boot) when the code is
no release's, and step 8's `implementation.entryPoint()` check (`implementation-entrypoint-mismatch`
at boot) when it is an older release built for EntryPoint v0.7.

## The single-chain (on-premises) profile

An on-premises deployment sets `CHAIN_ID`, `RPC_URL` and `BUNDLER_URL` and is done (MC-88). It
never supplies `GIANO_CHAINS`, never sees a chain picker, never supplies a `chainId` on a backend
request, and its operator needs no knowledge of the multi-chain shape (MC-90). Single-chain is
the degenerate case of N, not a separate build or mode (MC-86, MC-87).

The things it **does** need, and which are easy to miss: **EntryPoint v0.9 and CreateX at their
canonical addresses** (steps 1 and 2). A private chain will have neither; without EntryPoint the
implementation is not release code, and without CreateX nothing can be deployed at all.

## Per-chain operating costs (recurring)

Serving a chain costs, per chain and forever (MC-75, MC-98):

- the bundler executor account funded on that chain, monitored
  (`giano_bundler_executor_balance_wei`, labelled by chain);
- a staked, funded paymaster deposit, monitored (low-balance alerting);
- an RPC endpoint, and the bundler's path for that chain, monitored (`giano_chain_available`,
  `giano_bundler_chain_ready`, per-chain watcher lag metrics);
- for every sponsoring tenant, a funded per-chain balance — tenants fund per chain, and
  balances never pool across chains (D7).
