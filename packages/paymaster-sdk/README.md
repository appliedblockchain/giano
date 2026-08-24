# @appliedblockchain/giano-paymaster-sdk

Everything needed to read and administer a Giano sponsorship paymaster from outside the chain —
with the signer supplied by the caller, never by this package.

```ts
import { GianoPaymasterClient } from '@appliedblockchain/giano-paymaster-sdk';
import { createPublicClient, http } from 'viem';

const paymaster = new GianoPaymasterClient({
  address: '0x…',
  publicClient: createPublicClient({ transport: http(rpcUrl) }),
});

const overview = await paymaster.getOverview();
// → configuration, stake, solvency, every tenant with its balance, signers, role holders
```

## The signer boundary

The SDK takes a viem **wallet client**, not a key. It has no parameter that accepts a private key,
a mnemonic or a keystore, and it never constructs an account. The caller builds a wallet client
from whatever custody it actually uses and hands it over already able to sign:

```ts
// a browser extension                     // a script, or the management CLI
custom(window.ethereum)                    privateKeyToAccount(process.env.KEY)
// a hardware wallet, a KMS transport, a Safe — the SDK cannot tell the difference
```

That is what lets the same calls run in an admin browser tab and in an operations script. Reads
need no wallet at all; a client constructed without one throws `SignerRequiredError` on any write
rather than failing somewhere less obvious.

## What you can read

The tenant roster is an enumerable on-chain set, so **an overview needs no backend and no log
replay**:

| | |
| --- | --- |
| `getOverview()` | everything below, in one consistent snapshot |
| `getConfig()` | EntryPoint, default fee, overhead allowance, penalty bps, paused |
| `listTenants()` | every tenant with balance, deficit, effective fee, status |
| `getTenant(id)` | one tenant — accepts a UUID or a `bytes16` id |
| `getSolvency()` | `Σ balances + treasury ≤ deposit`, evaluated |
| `getStakeInfo()` | deposit, stake, unstake delay, unlock time |
| `getSigners()`, `getRoleHolders()`, `getRolesOf(account)` | authority |
| `getHealth()` | the checks `giano-doctor` runs, same thresholds |
| `getSponsorships()`, `watchSponsorships()` | settled sponsorships |
| `getTenantSlugs()` | the one field that needs logs — slugs are emitted, not stored |
| `assertDeployed()` | catches a wrong address or a wrong chain, in a sentence |

`getHealth()` is a pure function of an overview (`assessHealth`), so a UI can re-evaluate it
against data it already has, and it cannot disagree with the deployment gate.

## What you can write

Every write is **simulated before it is signed**, which is where the legible failure comes from: a
missing role costs nothing to discover and arrives as a typed error naming the role, rather than as
a reverted transaction and an ABI trace.

```ts
try {
  await paymaster.withdrawFees(to, parseEther('1000'));
} catch (error) {
  // ExceedsTreasuryError: cannot withdraw 1000 ETH: only 0 ETH has accrued to the treasury.
  // The cap is deliberate — without it this path would reach tenant funds.
}
```

| Role | Calls |
| --- | --- |
| — (anyone) | `depositFor` |
| the tenant's own withdrawal address | `withdrawTenant` |
| `TENANT_ADMIN_ROLE` | `registerTenant`, `setTenantEnabled`, `setTenantWithdrawAddress` |
| `FEE_ADMIN_ROLE` | `setDefaultFee`, `setTenantFee` |
| `FEE_COLLECTOR_ROLE` | `withdrawFees` |
| `SIGNER_ADMIN_ROLE` | `addSigner`, `removeSigner` |
| `PARAM_ADMIN_ROLE` | `setPostOpGasAllowance`, `setPenaltyBps` |
| `PAUSER_ROLE` | `pause`, `unpause` |
| `STAKE_ADMIN_ROLE` | `addStake`, `unlockStake`, `withdrawStake` |
| `ROLE_ADMIN` | `grantRole`, `revokeRole` |

Writes return `{ hash, wait() }` rather than blocking until confirmation, so a UI can show
"submitted" before it shows "confirmed".

`ROLE_DESCRIPTIONS` carries what each role may and — the half that matters — may **not** do.

## Tenant ids

The contract keys tenants by `bytes16`; the backend uses the tenant's UUID directly, so there is no
second identifier to keep in step. Every method accepts either spelling.

```ts
toTenantId('3f2504e0-4f89-11d3-9a0c-0305e82c3301'); // → '0x3f2504e04f8911d39a0c0305e82c3301'
toTenantUuid('0x3f2504e04f8911d39a0c0305e82c3301'); // → '3f2504e0-4f89-…'
```

Anything that is not one of those two spellings is rejected: an id that parsed by accident would
address a *different* tenant, and the contract would report that only as `UnknownTenant`.

## The walkthrough

`demo/cli.ts` runs every use case against a real chain, printing what it is about to do, why the
contract behaves that way, and the exact call — then the result. It is meant to be read alongside
the output.

```bash
pnpm paymaster:demo                    # from the repo root; every step
pnpm paymaster:demo --list             # step names
pnpm paymaster:demo --step errors      # just the refusals
```

On a local devnet it writes by default; anywhere else it explains each write instead unless you
pass `--write`. It needs a deployed paymaster — see `packages/contracts` for `hh:deploy:paymaster`
and `provision:paymaster`.

## The management CLI

`giano-paymaster` is the same client behind a command line, for development and operations.

```bash
pnpm paymaster status                  # config, funds, solvency, roster
pnpm paymaster health                  # exits non-zero on any failure — usable as a gate
pnpm paymaster tenants
pnpm paymaster fund <tenant-id> 0.5
pnpm paymaster roles
pnpm paymaster help
```

Signing is by raw EOA private key (`--private-key`, `PAYMASTER_PRIVATE_KEY`, or anvil's key 0 on
chain 31337), which is a **development affordance**: a key on a command line is in your shell
history and your process table. State-changing commands confirm before sending unless `--yes` is
passed, and warn when signing against a non-local chain. Production role holders are timelocks,
which are not driven from here.

`--json` prints machine-readable output for scripting.

## See also

- `services/paymaster-admin` — the operator console, built on this package
- `packages/contracts/scripts/doctor.ts` — the deployment gate whose checks `getHealth()` mirrors
- `packages/wallet-core`'s `paymaster/` — the *other* paymaster surface: the ERC-7677 client a
  wallet uses to request sponsorship. Unrelated to administering the contract.
