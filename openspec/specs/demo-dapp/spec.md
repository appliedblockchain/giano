# demo-dapp Specification

## Purpose

The reference Giano dApp: an ordinary client integration that reaches every public SDK method, exercises every failure
path, and records every outcome so that a defect in Giano is reportable from what is on screen.

## Requirements

### Requirement: The demo depends only on the published Giano surface
The demo SHALL import Giano code only from `@appliedblockchain/giano-connector`'s default entry point. It SHALL NOT
import `@appliedblockchain/giano-contracts`, `@appliedblockchain/giano-wallet-core`, `-wallet-kit`, `-wallet-transport`,
or any workspace path. Anything a client needs and the demo cannot obtain through that surface SHALL be recorded as a
Giano finding, not worked around.

#### Scenario: Internal import is rejected
- **WHEN** a source file imports a Giano package other than the connector, or a relative path outside the demo
- **THEN** the demo's lint step fails naming the file and the forbidden import

#### Scenario: Package resolution matches a client install
- **WHEN** the connector is installed from GitHub Packages instead of the workspace
- **THEN** no source file changes; only the dependency specifier changes

### Requirement: Setup preflight at load
On load, and again on demand, the demo SHALL run setup checks and render each as pass, warn or fail with the operator
action that fixes it: wallet origin reachable and answering CORS from this origin (its version endpoint), this page's
own Cross-Origin-Opener-Policy header, each configured chain's RPC answering `eth_chainId` equal to its configured id,
each configured default token having code on its chain, browser storage available for session resume, and the
connector version against the wallet-api version. A failed check SHALL NOT block the rest of the page; the affected
control SHALL carry the warning.

#### Scenario: Wallet origin unreachable or CORS-blocked
- **WHEN** the version fetch to the wallet origin fails
- **THEN** the preflight shows "wallet origin unreachable or this origin is not in the tenant's corsOrigins", and the
  transactions card warns that receipts will not be readable before any send

#### Scenario: COOP header present
- **WHEN** this page is served with `Cross-Origin-Opener-Policy: same-origin`
- **THEN** the preflight fails naming the header and the value to use instead, before any popup is attempted

#### Scenario: RPC on the wrong network
- **WHEN** a chain's RPC returns an `eth_chainId` different from the configured chain id
- **THEN** that chain is marked misconfigured and its write controls are disabled until fixed

#### Scenario: Version skew
- **WHEN** the connector version is newer than the wallet-api version
- **THEN** the preflight warns and cites the upgrade order

#### Scenario: All checks pass
- **WHEN** every check passes
- **THEN** the preflight collapses to a single "setup verified" line with a Re-run control

### Requirement: Session lifecycle through the provider
The demo SHALL connect with `eth_requestAccounts` from a user gesture, restore a cached session with `eth_accounts`
without opening a popup, reflect `accountsChanged`, `connect`, `chainChanged` and `disconnect` events, expose
`disconnect()` and `wallet_revokePermissions`, and display `isConnected()`, `chainId` and `supportedChainIds`.

#### Scenario: Connect from a gesture
- **WHEN** the user clicks Connect on the selected chain
- **THEN** the wallet popup opens, and on success the granted account and granted chain are shown and a ledger entry
  records the accounts returned and the supported chain ids advertised

#### Scenario: Session resume
- **WHEN** the page reloads with a cached session for the selected chain
- **THEN** the account is shown without a popup and the ledger records "resumed from cache"

#### Scenario: Provider event
- **WHEN** the provider emits any event
- **THEN** an event-log entry with event name and payload is appended and remains visible

#### Scenario: Session ended by the wallet
- **WHEN** the provider emits `disconnect` with code 4900 because the wallet no longer recognises the session
- **THEN** the demo shows a reconnect prompt in the header, not only an event-log line

#### Scenario: Granted chain read back
- **WHEN** the user triggers the "read eth_chainId" control
- **THEN** the value is shown next to the configured chain id and a difference is recorded as a violation

#### Scenario: Revoke and disconnect
- **WHEN** the user triggers `wallet_revokePermissions` or `disconnect()`
- **THEN** the account clears, a `disconnect` event entry is recorded, and `eth_accounts` afterwards returns an empty
  array (also recorded)

### Requirement: Chain selection is a UI affordance
The demo SHALL present the chains from runtime configuration as a selector. Selecting a chain SHALL construct or reuse a
provider bound to that chain; it SHALL never call `wallet_switchEthereumChain`. The demo SHALL also accept a free-form
chain id and RPC URL to connect to a chain not in configuration.

#### Scenario: Select a configured chain
- **WHEN** the user selects a chain
- **THEN** all subsequent actions go through that chain's provider and every ledger entry names the chain by id and name

#### Scenario: Unserved chain refused
- **WHEN** the user connects with a chain id the wallet origin does not serve
- **THEN** the ledger shows error code 4902, the requested chain id and the wallet's supported chain ids, and no
  passkey prompt occurred

#### Scenario: Served but unavailable chain
- **WHEN** the wallet origin reports the chain as served but unreachable
- **THEN** the ledger shows error code 4901 and the demo offers Retry

#### Scenario: Explicit switch or add refused
- **WHEN** the user triggers the "attempt wallet_switchEthereumChain" or "attempt wallet_addEthereumChain" control
- **THEN** the ledger records error 4200 with the wallet's message; a success is recorded as a violation

#### Scenario: Provider options are visible and editable
- **WHEN** the user opens the provider options for a chain
- **THEN** `walletApiPath` and the storage backend (browser storage or in-memory) are shown and can be changed, and
  the next provider constructed for that chain uses them

### Requirement: Address identity across chains is asserted
The demo SHALL compare the account granted by each chain's provider against the first granted account. Agreement SHALL
be displayed as an invariant held; disagreement SHALL be displayed as a violation banner that persists until dismissed
and is written to the ledger with both addresses and both chain ids.

#### Scenario: Same address on a second chain
- **WHEN** the user connects on a second chain
- **THEN** the identity panel lists both chains with the same address and the status "identical"

#### Scenario: Different address on a second chain
- **WHEN** a second chain grants a different account
- **THEN** a violation banner names both addresses and chains, the ledger records it, and the banner is not auto-dismissed

### Requirement: Every write method is reachable
The demo SHALL provide controls for `eth_sendTransaction` (native value and arbitrary calldata to an arbitrary target),
`personal_sign`, `eth_sign`, `eth_signTypedData_v4`, `eth_prepareUserOperation`, `eth_signUserOperation`,
`eth_sendSignedUserOperation`, `signed_eth_call` and `waitForUserOperationReceipt`. Each SHALL show the exact request
sent and the exact response or error received.

#### Scenario: Send and wait
- **WHEN** the user sends a transaction and it is accepted
- **THEN** the ledger entry shows the userOp hash immediately, then the receipt with transaction hash, block, `success`,
  `sender`, `paymaster`, `actualGasCost`, and the native balance before and after

#### Scenario: Raw user-operation pipeline
- **WHEN** the user runs prepare, sign and send as three separate steps
- **THEN** each step's input and output is shown, the signed user operation is visible in full, and the final hash is
  awaited like any other

#### Scenario: Signed read
- **WHEN** the user performs `signed_eth_call` against the default token's `privateBalanceOf`
- **THEN** the result is shown, and a call without `to` or `data` shows the wallet's validation error in full

#### Scenario: Receipt not found within the connector's deadline
- **WHEN** `waitForUserOperationReceipt` times out
- **THEN** the entry shows the timeout, keeps the userOp hash, and offers "keep waiting", which polls the receipt again
  for the same hash

#### Scenario: Reverted operation
- **WHEN** a receipt returns `success: false`
- **THEN** the entry is marked failed, the receipt is still shown in full, and the revert reason is shown when present

### Requirement: Gas payer is declared and attributed
Each transaction control SHALL let the user declare the expected payer: sponsored by the application, or paid by the
account. After the receipt arrives the demo SHALL attribute the actual payer from the receipt's `paymaster` field and
the sender's native balance delta. A mismatch between declared and actual payer SHALL be flagged on the entry.

#### Scenario: Sponsored as expected
- **WHEN** the user declares "sponsored" and the receipt carries a paymaster address and the native balance is unchanged
- **THEN** the entry shows "sponsored by <paymaster>" and "as declared"

#### Scenario: Refused before approval
- **WHEN** sponsorship is refused in the wallet and the user closes the popup
- **THEN** the entry shows error 4001 annotated "closed by the user or refused in the wallet: the application cannot
  tell which", points at the wallet console for the refusal reason, and shows the reason string when the wallet
  includes it

#### Scenario: Self-paid with insufficient balance
- **WHEN** the user declares "paid by the account", the account has no native balance and the wallet origin does not
  sponsor on that chain
- **THEN** the entry shows the wallet's error in full (including any AA-prefixed EntryPoint reason) and a link to the
  funding affordance

#### Scenario: Declared self-paid but sponsored
- **WHEN** the user declares "paid by the account" and the receipt shows a paymaster
- **THEN** the entry is flagged "payer differs from declaration" and the flag persists

### Requirement: Native balance and funding
The demo SHALL show the account's native balance on the selected chain, refresh it after every operation, and offer a
funding affordance: a copyable address with a faucet hint, and on a chain whose node accepts the development
`anvil_setBalance` method, a "fund from devnet" control.

#### Scenario: Devnet funding
- **WHEN** the user clicks "fund from devnet" on a development chain
- **THEN** the balance updates and the ledger records the method and result

#### Scenario: No devnet method
- **WHEN** the node rejects `anvil_setBalance`
- **THEN** the control is hidden after the first probe and the copyable address with faucet hint remains

### Requirement: ERC-20 section
The demo SHALL provide a token section prefilled with the selected chain's default token address from runtime
configuration, allow any token address, read name, symbol, decimals, balance and allowance, and provide mint, transfer,
approve and EIP-2612 permit signature controls. Token balances before and after each operation SHALL be recorded.

#### Scenario: Mint the default token
- **WHEN** the user mints an amount of the default token
- **THEN** the receipt is recorded and the token balance delta equals the minted amount

#### Scenario: Token without permit
- **WHEN** the user requests a permit signature for a token that has no `nonces()`
- **THEN** the entry records "no EIP-2612 support" with the underlying error and no popup is opened

#### Scenario: Default token absent on a chain
- **WHEN** the selected chain has no default token configured
- **THEN** the field is empty, the section says so, and every other control still works with a user-supplied address

### Requirement: Wallet management entry
The demo SHALL open wallet management through the provider's `openWalletManagement()` only, from a user gesture, and
SHALL record whether the promise resolved with no data or rejected.

#### Scenario: Management closed
- **WHEN** the user closes the management view
- **THEN** the ledger records "closed, no data returned"; any returned data is recorded as a violation

### Requirement: Failure paths are controls
The demo SHALL provide dedicated controls that provoke: user rejection, popup blocked (wallet call issued after the
user gesture has expired), unserved chain, sponsorship refusal for an unlisted contract, self-paid with no balance, and
malformed input (invalid address, invalid hex). Each SHALL record the typed error (class name, code, message, data).

#### Scenario: Origin not allow-listed
- **WHEN** the user triggers the "connect from a disallowed origin" control (a provider constructed against the other
  tenant's wallet origin, which does not allow-list this dApp)
- **THEN** the ledger records `HandshakeRefusedError` with reason `origin-not-allowed` and the operator action "add this
  origin to the tenant's allowedDappOrigins"; no chain list is expected in the refusal

#### Scenario: Popup blocked
- **WHEN** the user triggers the delayed-call control
- **THEN** the ledger records a transport error with code `POPUP_BLOCKED` (or the wallet result, if the browser allowed
  the popup, marked "browser allowed the popup")

#### Scenario: User rejection
- **WHEN** the user rejects in the wallet
- **THEN** the ledger records RPC error 4001 and the action's input

### Requirement: Outcome ledger
Every action SHALL append a ledger entry containing: timestamp, section, method, params as sent, chain id and name,
wallet origin, declared payer, outcome status, userOp hash, transaction hash, receipt, balances before and after, error
(name, code, message, data), and duration. Entries SHALL persist across reloads in browser storage, SHALL be exportable
as JSON and copyable individually, and SHALL never be removed except by an explicit Clear control or by the retention
cap: the ledger keeps at most 500 entries, evicts the oldest beyond that, shows the eviction count, and exports only
retained entries.

#### Scenario: Reload keeps the record
- **WHEN** the page reloads
- **THEN** all previous entries are still shown in order

#### Scenario: Export
- **WHEN** the user clicks Export
- **THEN** the full ledger is copied as JSON including the runtime configuration and the connector's advertised version

### Requirement: Wagmi and RainbowKit adapters reachable
The demo SHALL include a section that mounts wagmi with `createGianoConnector` for the selected chain and exposes
connect, account state, `switchChain` (expected `UnsupportedChainSwitchError`) and `waitForUserOperationReceipt`, and
SHALL mount the RainbowKit adapter `giano()` in the same section so the connect modal lists Giano.

#### Scenario: RainbowKit lists Giano
- **WHEN** the user opens the RainbowKit connect modal
- **THEN** Giano appears as a wallet and connecting through it grants the same account as the raw provider

#### Scenario: Switch chain via wagmi
- **WHEN** the user requests a chain switch through wagmi
- **THEN** the ledger records the typed `UnsupportedChainSwitchError`

### Requirement: Styling and branding constraints
The demo SHALL use Chakra UI components and theme tokens only. It SHALL contain no CSS files, no `css` prop, no
`globalCss`, and no inline `style` attributes. Brand tokens SHALL live in one theme file and reflect Applied Blockchain
branding as provided by the Applied Edge Design System.

#### Scenario: Custom CSS rejected
- **WHEN** a stylesheet import, `css` prop or `style` attribute is added
- **THEN** the lint step fails

### Requirement: The demo is the documented integration
Code snippets in `specs/DEVELOPER-GUIDE.md` §4 and `specs/INTEGRATION.md` §9 SHALL correspond to code in the demo. A
divergence SHALL be treated as a defect and fixed in whichever is wrong.

#### Scenario: Snippet drift
- **WHEN** a documented call shape differs from the demo's
- **THEN** the review checklist in tasks flags it and one of the two is corrected before merge
