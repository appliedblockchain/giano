# Giano paymaster admin

An operator's view of a Giano sponsorship paymaster: tenant balances, treasury, roles, health and
settled sponsorships — all read straight from the chain.

There is no backend. The console talks to an RPC endpoint and nothing else, so it needs no login,
no API key and no database, and it cannot show you anything the chain does not already say. That is
deliberate: an operational view whose numbers come from a cache can be wrong in the one situation
where being wrong matters most.

```bash
pnpm demo:admin            # from the repo root → http://localhost:4402
```

## What it shows

- **Overview** — the solvency invariant (`Σ tenant balances + treasury ≤ deposit`), deposit, stake
  and pricing. A breach is rendered as an insolvency, not a warning.
- **Tenants** — the whole roster with balances, deficits and effective fees, enumerated on-chain.
- **Roles** — who holds what, and what each role may and may **not** do. `DEFAULT_ADMIN_ROLE` is
  shown precisely because it should be empty.
- **Settings** — signing keys, fees, parameters, stake, treasury, pause.
- **History** — settled sponsorships, with gas, fee and overhead separately.
- **Health** — the checks `giano-doctor` runs, at the same thresholds.

## Connecting a wallet

Reads need no wallet. Connecting one enables the actions the connected account's roles allow;
everything else stays visible but disabled, with the role it would need named underneath — hiding a
control just produces a support ticket.

The console never sees a key. It asks an injected EIP-1193 wallet to sign, which is the only shape
that works when the role holders are hardware wallets and timelocks. It checks the wallet's chain
rather than silently switching it: quietly moving a hardware wallet to another network is a good
way to sign a treasury withdrawal against the wrong deployment.

Withdrawing a tenant's balance is deliberately absent. Only that tenant's own registered withdrawal
address can do it, and no role on the paymaster can — including every role at once.

## Configuration

Runtime, from `/config.json`, fetched before the first render — not build-time `VITE_` variables.
One published image serves every deployment; an image baked to a single chain is how a production
console ends up pointed at a devnet.

The file declares the deployments the console may administer. That list is the whole of what it can
reach: an operator picks between environments someone configured deliberately, and cannot point the
console at an arbitrary chain by typing into it.

```json
{
  "deployments": [
    { "label": "base sepolia", "chainId": 84532, "rpcUrl": "https://…", "paymasterAddress": "0x…", "refreshSeconds": 30 },
    { "label": "local devnet", "chainId": 31337, "rpcUrl": "http://localhost:8545", "paymasterAddress": "0x…", "refreshSeconds": 10 }
  ]
}
```

| Key | |
| --- | --- |
| `label` | how an operator tells this environment apart; shown in the header |
| `chainId` | required |
| `rpcUrl` | required; `/rpc` uses the container's same-origin proxy |
| `paymasterAddress` | the proxy. See the caveat below — set it |
| `refreshSeconds` | poll interval; `0` disables polling |

With more than one entry the header shows a **picker**; with one it shows the label as a badge. The
choice is remembered in `localStorage`, keyed on chain and address rather than on the label, so
rewording a label never silently moves the selection to another environment.

Switching deployments **drops the connected wallet**. It was bound to the old chain and its roles
were read from the old paymaster, so keeping it would offer actions the account may not hold on the
deployment now on screen. Reconnecting is one click.

> **`paymasterAddress` is optional in the schema but required in practice.** Leaving it out asks the
> SDK to resolve the address from the contracts registry, and no chain in `packages/contracts/addresses.ts`
> currently declares a `sponsorshipPaymaster`. Omit it and the console fails to start, loudly.

`public/config.json` is the dev copy. The container renders `docker/config.json.template` from
either `GIANO_DEPLOYMENTS` (a JSON array — the general form) or the single-deployment shorthand
`GIANO_CHAIN_ID` / `GIANO_RPC_URL` / `GIANO_PAYMASTER_ADDRESS` / `GIANO_ENVIRONMENT_LABEL` /
`GIANO_REFRESH_SECONDS`.

## Addresses

Addresses and other on-chain identifiers are **never abbreviated**, and **clicking one copies it**.
An operator checking that a role holder is the timelock is comparing the whole value, and
`0x1234…5678` hides exactly the middle that distinguishes two addresses from the same deployer.

## In the e2e stack

`deploy/docker-compose.e2e.yml` publishes it on 8083, and portless serves it as
**http://paymaster.localhost**. Open it beside http://app.localhost: a sponsored send from the
sample dApp shows up as a falling tenant balance and a new row under **History**.

It waits for the sponsorship provisioner, so it shows a provisioned deployment rather than an empty
roster that looks like a bug.

## Built on

`@appliedblockchain/giano-paymaster-sdk` — every read and write here is one of its calls, including
the health checks, which it evaluates locally from the overview already on screen.
