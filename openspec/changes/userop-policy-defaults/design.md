## Context

The relay policy runs on every operation sent through `POST /v1/userops` or `eth_sendUserOperation` on `/v1/bundler/:chainId`, after the session is resolved and before the operation reaches the bundler. Its caps resolve per (tenant, chain): deployment env ← chain descriptor `walletApi.policy` ← tenant base ← tenant `perChain[chainId]`. Its allowlists resolve from `perChain[chainId]`, else the chain descriptor (MC-61).

The sponsorship rules (`evaluateSponsorship`) are a different check: they decide whether a tenant pays for an operation. The relay policy applies to every relayed operation, sponsored or not.

## Decisions

### D1: What the policy protects

1. **The shared bundler and its executor balance.** Every tenant's operations go through one bundler, which simulates each one and fronts the gas from its executor keys. Oversized gas limits make simulation expensive and tie up an executor lane; an operation it cannot recover the cost of drains the executor.
2. **Each tenant.** A tenant's users must not be able to spend through a paymaster or at targets the tenant did not choose, or bill another tenant.
3. **Giano as an operator.** Giano runs the relay, so it must be able to show what it relayed and why, and must not relay an operation for a wallet other than the session's.

It is not there to restrict what a wallet may do with its own funds. A tenant that wants that sets allowlists.

### D2: Fee caps come from a table of known chains

A chain-agnostic cap cannot be right on both Ethereum and Base: fees differ by three orders of magnitude. The fee caps resolve per chain:

`descriptor walletApi.policy` > `USEROP_MAX_*_FEE_PER_GAS` if set > known-chain default > fallback (500 gwei / 500 gwei, the old default)

Then the tenant's base and per-chain overrides apply as before.

| Chain | maxFeePerGas | maxPriorityFeePerGas |
|---|---|---|
| Ethereum (1) | 300 gwei | 20 gwei |
| Sepolia (11155111) | 500 gwei | 50 gwei |
| OP Mainnet (10), Base (8453), Base Sepolia (84532) | 10 gwei | 1 gwei |

Each is far above normal fees (Base runs at about 0.01 gwei) and well below the old cap, so it fires on a client bug or an attack, not on congestion. Sepolia keeps 500 gwei because its spikes are large and its funds worthless. Local devnets and Silent Data have no entry: their fees are set by whoever runs them, so they use the env or the fallback.

The table lives in wallet-api (`src/services/chain-fee-caps.ts`), the only consumer.

A production deployment refuses to boot when a served chain gets the fallback. Production must state a cap for a chain Giano has no default for.

The env vars lose their zod default so "set" can be told from "unset". An operator who set them keeps their value on every chain.

### D3: The new gas caps

| Rule | Field | Default | Why |
|---|---|---|---|
| `pre-verification-gas-cap` | `preVerificationGas` | 10,000,000 | Paid to the bundler for calldata and, on OP Stack chains, the L1 data fee in L2 gas. With L2 gas at a fraction of a gwei that can reach millions, so the default is generous. |
| `paymaster-verification-gas-cap` | `paymasterVerificationGasLimit` | 1,000,000 | Runs in the bundler's validation simulation. Matches the bundler's own simulation ceiling. |
| `paymaster-post-op-gas-cap` | `paymasterPostOpGasLimit` | 1,000,000 | Reserved from the paymaster's deposit at the operation's fee. |

An operation with no paymaster passes the paymaster rules ("no paymaster in op"). Each cap is settable as an env default, in a chain descriptor and in a tenant policy (base and `perChain`), like the existing gas caps.

### D4: The factory is not capped

`factory` and `factoryData` deploy the sender when it has no code. A mismatched factory can do nothing an attacker benefits from:

- `sender-binding` requires `sender` to be the session's wallet.
- The EntryPoint refuses an operation whose `initCode` does not deploy exactly `sender` (AA14) and one with `initCode` for a sender that already has code (AA10). The Giano wallet address is a CREATE2 address of the Giano factory, so no other factory can produce it.
- The bundler simulates validation before it includes an operation, so the refusal costs a simulation and no gas. That simulation is bounded by `verification-gas-cap`, and `factoryData`'s size by `pre-verification-gas-cap` and the request body limit.
- EIP-7702 initCode (`0x7702…`) is already refused by the request schema.

So the factory is left unbounded on purpose.

### D5: A broken tenant policy fails closed, in the policy itself

`mergePolicy` reports a parse failure instead of falling back. `evaluatePolicy` runs a first rule, `tenant-policy`, that fails when it did. Putting it in the rule list means the refusal reaches the audit row, the `policy-rejected` answer and `giano_userop_policy_rejections_total{rule="tenant-policy"}` the same way every other refusal does, so no caller can skip it. The relay also logs it at error level with the tenant and the parse issues: it means a stored row no longer matches the schema, and an operator has to fix it.

The rate limiter reads only the relay limit from the policy; with a broken policy it uses the deployment default. The operation is refused anyway.

### D6: Allowlists are `"any"` or a non-empty list, and the deployment's choice is the default

- The tenant schema accepts `"any"` or a non-empty list for `perChain[chainId].allowedTargets` and `.allowedPaymasters`. An empty list is refused on write: it reads as "nothing allowed" but has always meant "any", which is exactly the confusion R5 is about.
- A stored empty list, written before this change, is read as `"any"`, which is what it meant when it was written. This avoids a data migration that would rewrite rows outside the tenant history. The upgrade runs before a patch is validated, so a patch that does not touch the policy is not refused for it.
- A tenant with no `perChain` entry for a chain inherits the chain's allowlists, as today. That inheritance is the recorded choice: the deployment's. (`specs/MULTICHAIN_SPECS.md` §9.5 says "absent an entry, the tenant permits nothing on that chain"; the code never did that. The spec text is corrected to match.)
- A chain descriptor's allowlist and `USEROP_ALLOWED_*` accept `"any"`. An empty descriptor list still reads as any, so existing chain documents keep working.
- **Production boot.** `GIANO_DEPLOYMENT_CLASS=production` refuses to boot unless every served chain states both allowlists (`"any"` or addresses), in its descriptor or the single-chain env vars. It does **not** refuse to boot because of a tenant row: tenants are written at runtime, the service must boot with none, and one bad row must not stop every tenant's relay. A tenant row is guarded by the write schema and, if it still goes bad, by D5.

## Risks

- **A fee cap below a real spike refuses operations.** The caps are 100× to 1000× normal fees. A refusal is counted per chain and rule; the README names the alert to set.
- **The PVG default is loose on L1.** 10M gas is far above what an L1 operation needs. A per-chain PVG table would fix it but needs measurement first; the cap is still a bound.
- **Admin API clients that send `[]`** now get a 400. The only known client is the paymaster console, updated here.

## Open Questions

- Should the fee caps, or a "cost" cap (fee × total gas), also be enforced by the bundler? Out of scope here.
- Should non-production deployments warn at boot when an allowlist is not stated? Left out to keep local stacks quiet.
