# Giano

An ERC-4337 smart wallet that users sign in to with a Passkey, from inside a Tenant's dApp.
Applied Blockchain runs it as a Hosted Deployment for many Tenants. A company can also host it itself.

## Language

### Product

**BYO Wallet**:
A Wallet Origin app that a Tenant builds and hosts itself, with wallet-kit and wallet-api, instead of using the Stock Wallet. It has no privilege the Stock Wallet lacks, and wallet-api cannot tell the two apart. In the demo, the app named "BYO Wallet" is wallet-byo, one example of it.
_Avoid_: Custom wallet, Bring-your-own UI

**Connection Grant**:
The user's approval that one dApp origin may see their Smart Account, given on the Consent Screen when the dApp connects. The Wallet Origin stores it, and the user can revoke it.
_Avoid_: dApp session, Permission (too vague)

**Consent Screen**:
The Wallet Origin screen that shows what is asked, by whom and on which chain. Nothing is signed without it.
_Avoid_: Approval modal, Consent UI

**dApp**:
The Tenant's application that the user is using. It installs the connector and points to a Wallet Origin, nothing else.
_Avoid_: Client app, Host app

**Hosted Deployment**:
The Giano deployment that Applied Blockchain runs for many Tenants. The primary model; a company can also host Giano itself, on premise.
_Avoid_: Hosted service, Standalone service, SaaS, The platform

**Review Screen**:
The Consent Screen for a transaction. It shows the approve button only after the transaction description and the sponsorship check are ready.
_Avoid_: Confirm screen, Transaction modal

**Stock Wallet**:
The Wallet Origin app that Giano provides: wallet-web.
_Avoid_: Default wallet, Wallet UI

**Two-Origin Model**:
Every integration runs in two browser contexts: the dApp's own origin and a Wallet Origin popup. All trust lives on the Wallet Origin.
_Avoid_: Embedded mode (the retired 0.x model, where the dApp was the wallet)

**Wallet Origin**:
The dedicated web origin of one Tenant. Every passkey prompt, signature, consent and Wallet Management action happens there, in a popup.
_Avoid_: Wallet domain, Wallet (too vague)

### Packages

**connector**:
The only package a dApp installs, `packages/connector`. It sends every wallet action to the Wallet Origin popup, and includes wagmi and RainbowKit adapters.
_Avoid_: Thin SDK, dApp SDK, Thin provider (one part of it)

**giano-contracts**:
The package with Giano's Solidity contracts, their ABIs and the deployed address registry, `packages/contracts`. It also holds the deploy scripts and the Doctor.
_Avoid_: Contracts (too vague, that is the deployed code), Contracts package

**paymaster-sdk**:
The library that reads the Paymaster's whole state and administers it on chain, `packages/paymaster-sdk`. The caller supplies the signer. paymaster-admin uses it.
_Avoid_: Paymaster client, Paymaster library

**tx-describe**:
The library that turns a transaction into a human-readable description, using Transaction Mappings, `packages/tx-describe`. wallet-kit and wallet-api use it.
_Avoid_: Describer, Clear signing (the ERC-7730 standard)

**wallet-core**:
The lower-level library under wallet-kit, `packages/wallet-core`. It builds the Smart Account, turns transactions into User Operations and talks to wallet-api. A dApp never installs it.
_Avoid_: Core (too vague)

**wallet-kit**:
The library a Wallet Origin app is built from, `packages/wallet-kit`: the wallet-transport host, the consent flow and Wallet Management. It draws no UI; each app draws its own Consent Screen. The Stock Wallet and every BYO Wallet use it.
_Avoid_: Wallet SDK, Kit (too vague)

**wallet-transport**:
The postMessage protocol between the dApp and the Wallet Origin popup, and the package that implements it, `packages/wallet-transport`. Each end accepts messages only from the expected origin.
_Avoid_: Popup protocol, Bridge

### Services

**bundler**:
Giano's own ERC-4337 submission service, `services/bundler`. Only wallet-api calls it.
_Avoid_: Alto (retired), Relayer

**custom-example**:
The demo dApp, `services/custom-example`. Run it to see Giano working.
_Avoid_: Example app, Demo (too vague), dApp Fixture (the end-to-end test page)

**devnet**:
A local anvil chain state with Giano's contracts already deployed at their Deterministic Addresses. `e2e/devnet` generates the state, and `services/devnet` packages it as an image. The E2E Stack runs on it; local development deploys onto an empty anvil instead.
_Avoid_: Local chain, Anvil (the tool), dev (that is an Environment)

**paymaster-admin**:
The console where Platform Admins manage Tenants and the Paymaster, `services/paymaster-admin`. Connected to wallet-api, it needs sign-in. On its own, it works on chain only, through a connected wallet.
_Avoid_: Paymaster Console, Platform console, Operator console, Admin console

**wallet-api**:
Giano's backend, `services/wallet-api`. It verifies passkeys, holds Wallet Sessions and Tenants, runs the Relay and the Sponsorship Service, and serves Platform Admins.
_Avoid_: Wallet API, Backend (too vague), API (too vague)

**wallet-web**:
The Stock Wallet, `services/wallet-web`: Giano's own Wallet Origin app, served as static files.
_Avoid_: Wallet frontend, Wallet UI

### Tenants

**Admin API**:
wallet-api's routes for one Tenant, authorised by a Tenant Admin Key.
_Avoid_: Tenant API, Platform API (that is for Platform Admins)

**Allowed dApp Origins**:
The dApp origins that a Tenant's Wallet Origin accepts requests from. The Wallet Origin app enforces its own configured list. wallet-api also stores a list per Tenant, but nothing reads it yet. An empty list refuses all; `*` allows all, for development only.
_Avoid_: CORS Origins (a separate list), Whitelist

**CORS Origins**:
Origins, besides the Wallet Origin, from which a browser may call wallet-api directly, such as a dApp that polls a receipt.
_Avoid_: Allowed dApp Origins (those reach the Wallet Origin, not wallet-api)

**Expected Origins**:
The origins where wallet-api accepts a Ceremony for a Tenant, usually just the Wallet Origin. Each must be the RP ID host or a subdomain of it.
_Avoid_: Related Origins (other domains, published for the browser), Allowed dApp Origins

**Open Registration**:
A Tenant setting. When it is on, any user can register a Passkey. When it is off, registration needs the Tenant Admin Key, so the Tenant authorises each new user.
_Avoid_: Public sign-up, Self-registration

**Related Origins**:
Other domains that the browser lets use a Tenant's Passkeys, through the WebAuthn feature Related Origin Requests. The Tenant Admin Key sets them, and wallet-api publishes them. wallet-api does not yet accept a Ceremony from them.
_Avoid_: ROR origins, Allowed dApp Origins (those can only send requests), Expected Origins (where wallet-api accepts a Ceremony)

**Relay Policy**:
A Tenant's limits on the User Operations the Relay accepts: gas and fee caps, rate limit, and allowed targets and paymasters per chain. Platform Admins edit it.
_Avoid_: Sponsorship policy (paymaster-admin's label for it), Policy (too vague)

**Tenant**:
One customer of a Giano deployment. It has exactly one Wallet Origin and one RP ID, equal to the Wallet Origin's host. These never change; a Tenant that needs a new origin is a new Tenant. It also has Tenant Admin Keys and a Tenant Balance.
_Avoid_: Client, Customer app, Application, Organisation

**Tenant Admin Key**:
A Tenant's own credential for the Admin API. With it the Tenant manages its Sponsorship Rules, Transaction Mappings and Related Origins, and can end its users' Wallet Sessions. It never authorises platform work.
_Avoid_: Admin key (too vague), API key

**Tenant State**:
`active`, `suspended` or `deleted`. Only an active Tenant serves traffic. Suspending is reversible; the Tenant Balance stays on chain and the Ledger keeps recording it. Only a suspended Tenant with no funds can be deleted, and deleting is permanent.
_Avoid_: Disabled (that is the on-chain flag), Paused (that is the Paymaster), Tenant status

**Transaction Mapping**:
An ERC-7730 descriptor a Tenant publishes for one of its contracts, so the Consent Screen can describe calls to it in plain words.
_Avoid_: Tx mapping, ABI mapping

### Accounts

**Account Factory**:
The contract that creates each Smart Account, `GianoSmartWalletFactory`. The address depends only on the Owners and a nonce, so it is known before the account exists.
_Avoid_: Factory (too vague), Deployer (that is the Canonical Deployer)

**Address Identity**:
One Passkey gives the same Smart Account address on every Served Chain.
_Avoid_: Same-address guarantee, Cross-chain address

**Ceremony**:
One WebAuthn registration or sign-in with a Passkey, verified by wallet-api.
_Avoid_: Passkey prompt, WebAuthn flow, Key Ceremony (that is key generation)

**Implementation**:
The contract that holds the code behind a proxy. Each Smart Account and the Paymaster is a proxy. An upgrade changes the Implementation, never the address.
_Avoid_: Logic contract, Singleton

**Owner**:
A key that controls a Smart Account: a Passkey or an Ethereum address, usually an EOA. Each Served Chain holds its own authoritative list, and the lists can differ until a change reaches every chain.
_Avoid_: Signer, Key holder

**Passkey**:
The user's device-held WebAuthn key, and the usual Owner of a Smart Account. A Wallet Session cannot replace its signature.
_Avoid_: Credential (except in WebAuthn code), Biometric

**RP ID**:
The WebAuthn relying party ID of a Tenant, equal to its Wallet Origin's host. Changing it orphans every Passkey made for it.
_Avoid_: Relying party, Domain

**Smart Account**:
The user's on-chain account: an upgradeable contract that its Owners control.
_Avoid_: Wallet (too vague), Account (too vague), Contract wallet

**Wallet Management**:
Viewing, naming, adding and removing a Smart Account's Owners, on the Wallet Origin. A dApp can only open it.
_Avoid_: Account settings, Key management

**Wallet Session**:
The token wallet-api gives the Wallet Origin after a Ceremony. It ends after 1 hour idle or 24 hours in total. It cannot sign.
_Avoid_: Session (too vague), Login, Auth token

### Transactions

**EntryPoint**:
The standard ERC-4337 contract that runs User Operations and holds the Paymaster's Deposit and Stake. Giano uses v0.9.
_Avoid_: Entry point contract

**Executor**:
A funded key of the bundler that submits User Operations on chain. It pays the gas first, and the EntryPoint pays it back.
_Avoid_: Relayer, Submitter, Timelock executor (a separate thing)

**Relay**:
The wallet-api step that checks a signed User Operation against the Relay Policy, records it, and only then sends it to the bundler.
_Avoid_: User Operation Relay, Policied relay, Policy gate

**User Operation**:
The ERC-4337 equivalent of a transaction. The Wallet Origin turns each transaction request into one.
_Avoid_: Transaction (when you mean a User Operation), Userop (in prose)

### Sponsorship

**Paymaster**:
Giano's paymaster contract. It checks each sponsorship approval, records the Tenant Balances and the Treasury, and charges each operation.
_Avoid_: Paymaster service (that is the Sponsorship Service)

**Sponsorship**:
Giano pays a User Operation's gas from a Tenant Balance, only for operations the Tenant's Sponsorship Rules allow.
_Avoid_: Gasless (the user's view, not the mechanism), Gas subsidy

**Sponsorship Approval**:
The Sponsorship Signer's signature that lets the Paymaster sponsor one User Operation. It is valid only for a short window.
_Avoid_: Authorisation (the code's name for it), Paymaster signature

**Sponsorship Rules**:
A Tenant's per-chain sponsorship settings: on or off, a cost cap per operation, and an allowlist of contracts and functions. Deny by default; only the Tenant Admin Key can write them. Wallet Management operations need no allowlist entry, up to a cost cap that Giano sets, but only while sponsorship is on for that chain and its allowlist is not empty. A Tenant can turn that off or lower the cap, but cannot raise it.
_Avoid_: Sponsorship policy, Sponsorship config, Policy (too vague), Wallet-Management Sponsorship

**Sponsorship Service**:
wallet-api's ERC-7677 endpoint. It checks the Sponsorship Rules, sets funds aside, and has the Sponsorship Signer approve the User Operation.
_Avoid_: Paymaster service, Paymaster API

**Sponsorship Signer**:
The key that approves each sponsored User Operation for the Paymaster. It holds no funds and lives in an HSM in production.
_Avoid_: Paymaster signer, Signing key (too vague)

### Paymaster funds

**Deficit**:
What a Tenant owes when a Settlement costs more than its Tenant Balance. A Tenant with a Deficit gets no new Sponsorship Approvals, and its next funding pays the Deficit first.
_Avoid_: Debt, Negative balance

**Deposit**:
The Paymaster's funds held by the EntryPoint, shared by all Tenants.
_Avoid_: Paymaster balance, Pool

**Emergency Stop**:
wallet-api stops approving sponsorship. Tenant withdrawals stay open.
_Avoid_: Kill switch, Pause (that is on chain)

**Ledger**:
wallet-api's off-chain record of Tenant Balances, charges and reservations. Balances and charges are a cache of the chain. Reservations exist only here; they stop parallel approvals from spending more than the balance.
_Avoid_: Accounting table, Books

**Pause**:
The on-chain stop of the Paymaster. It works even if the Sponsorship Signer leaks. Tenant withdrawals stay open.
_Avoid_: Freeze, Suspend (that is a Tenant)

**Platform Fee**:
A fixed fee per sponsored User Operation, paid into the Treasury. Each chain's Paymaster has a default, with an optional per-Tenant override.
_Avoid_: Service fee, Margin

**Reservation**:
Funds the Ledger sets aside when a Sponsorship Approval is signed. Released when the operation settles or the approval expires.
_Avoid_: Hold, Lock, In-flight reservation (the Paymaster's own hold during one bundle)

**Settlement**:
The accounting of one sponsored User Operation after it runs on chain.
_Avoid_: PostOp (the contract function), Payment

**Solvency Invariant**:
Tenant Balances plus the Treasury never exceed the Deposit.
_Avoid_: Invariant (too vague), Balance check

**Stake**:
Funds the Paymaster locks with the EntryPoint as a good-behaviour bond. Not the Deposit.
_Avoid_: Bond, Collateral

**Tenant Balance**:
A Tenant's share of the Deposit. Only operations sponsored for that Tenant spend it, and only the Tenant's Withdrawal Address can withdraw it.
_Avoid_: Paymaster balance, Credit, Wallet balance

**Treasury**:
The Platform Fees collected and not yet withdrawn.
_Avoid_: Fees balance, Revenue

**Watcher**:
The wallet-api process, one per chain, that reads Paymaster events into the Ledger and settles Reservations.
_Avoid_: Indexer, Listener

**Withdrawal Address**:
The only address that can withdraw a Tenant Balance. It is set when the Tenant is registered on the Paymaster, and changing it is a Timelocked Role's job.
_Avoid_: Payout address, Treasury (that is the Platform Fees)

### Paymaster roles

**Bootstrap Key**:
The key that holds every Timelocked Role, role admin included, during Provisioning, and gives them up at Handoff. It is never a Canonical Deployer.
_Avoid_: Bootstrap operator, Bootstrap admin (the first Platform Admins of a deployment)

**Handoff**:
Giving the Timelocked Roles to the Timelock and removing them from the Bootstrap Key, role admin last.
_Avoid_: Transfer, Migration

**Immediate Role**:
A Paymaster permission that takes effect at once and stays with an operational key: signer admin, param admin, pauser, stake admin, tenant admin and fee collector. The tenant admin role registers Tenants on chain; it is not a Tenant Admin Key.
_Avoid_: Operational role, Instant role

**Operator**:
The person who runs a chain's deployment and Provisioning, with the Paymaster Operator Key.
_Avoid_: Platform Admin (that is a paymaster-admin user), Deployer

**Paymaster Operator Key**:
The Operator's key. It stakes the Paymaster and funds Tenant Balances. During Provisioning it is also the Bootstrap Key.
_Avoid_: Operator (that is the person), Deployer key

**Proposer**:
The Timelock role that schedules and cancels changes. A Safe in production.
_Avoid_: Governor, Admin (too vague)

**Provisioning**:
The on-chain setup of a new Paymaster before Handoff: Sponsorship Signer, Stake, Tenant registration, funding and roles.
_Avoid_: Setup, Bootstrap (too vague), Sponsorship provisioner (the job that installs Sponsorship Rules)

**Timelock**:
The contract that holds the Timelocked Roles and delays each change it makes.
_Avoid_: Governance, Delay contract

**Timelocked Role**:
A Paymaster permission that only the Timelock holds after Handoff: role admin, upgrader, fee admin and withdrawal-address admin. The others are Immediate Roles.
_Avoid_: Delayed role, Admin (too vague)

### Platform administration

**Doctor**:
The command-line check of a chain's whole Giano deployment: contract code, Stake, Deposit, signers, roles, Timelock and Solvency Invariant.
_Avoid_: Health check, Verifier

**Drift**:
A difference between wallet-api's records and the Paymaster on one chain. paymaster-admin shows it in Health as a warning, and the Doctor reports it when given wallet-api's address.
_Avoid_: Mismatch, Desync

**Health**:
The verdict on one chain's deployment: `ok`, `warn` or `fail` for each check. paymaster-admin and the Doctor give the same verdicts for the checks they share.
_Avoid_: Status (too vague), `/healthz` (that is wallet-api's liveness route)

**Platform Admin**:
A staff member of the company that runs the deployment. Manages Tenants and other Platform Admins, and signs in with an EOA.
_Avoid_: Operator (that runs deployments), Admin (too vague), Super-admin

**Platform API**:
wallet-api's routes for Platform Admins only.
_Avoid_: Admin API (that is per Tenant), Operator API

### Deployment

**Canonical Deployer**:
The key that deploys Giano's contracts, except the Timelock, on every chain of one Network Class, and so decides their addresses. It holds no role, and only enough funds to pay for gas.
_Avoid_: Class deployer, Deployer (too vague)

**Chain Adoption**:
Putting Giano on a new chain, following the checklist in `specs/CHAIN-ADOPTION.md`. Passing the checklist is required, not advisory.
_Avoid_: Chain onboarding, Adding a chain

**Chain Profile**:
The public settings for deploying on one chain: Network Class, RPC, Contract Release, fees, Bootstrap Key, Timelock address, Proposers, timelock delays and address overrides.
_Avoid_: Chain config, Network config

**Contract Release**:
A frozen contract build. Deployments always use a Contract Release, never a fresh build. Separate from a release of the npm packages.
_Avoid_: Release (too vague), Contract version

**Deployment Class**:
`development`, `testnet` or `production`: how strict one wallet-api deployment must be. `GIANO_DEPLOYMENT_CLASS` sets it. `production` requires the Sponsorship Signer to be in an HSM.
_Avoid_: Network Class (that is per chain), Environment (that names the copy)

**Deployment Record**:
The committed file that lists what is deployed on one chain, and how each address was obtained.
_Avoid_: Deployment (too vague)

**Deterministic Address**:
The address a contract gets from its Canonical Deployer and a name label alone, through CREATE3. The bytecode does not change it.
_Avoid_: Canonical address, Expected address, CREATE2 address (retired)

**Deviation**:
Any departure from deterministic deployment, such as using an existing contract at another address, or a non-canonical deployer. Always recorded; on mainnet it needs a typed confirmation.
_Avoid_: Exception, Override (too vague)

**Environment**:
One running copy of Giano's services: `dev`, `stg` or `prd` on AWS, `reference` for a company that hosts Giano itself, or a local one such as the E2E Stack. `GIANO_ENVIRONMENT` names it. `infra/versions.json` sets the commit each AWS Environment runs.
_Avoid_: Stage, Network Class (that is per chain), devnet (that is a chain)

**Key Ceremony**:
The ABIP-8 procedure in which DevOps creates a sensitive key on a clean machine and records only its public address.
_Avoid_: Key generation (too vague), Ceremony (alone, that is WebAuthn)

**Network Class**:
`mainnet`, `testnet` or `local`. It chooses the Canonical Deployer, so every chain of a class shares the same addresses.
_Avoid_: Network type, Class (too vague), Environment (a separate thing), Deployment class (a separate thing)

**Rehearsal**:
A testnet deployment run on a fork of the real chain, with a stand-in deployer. It sends nothing to the real chain.
_Avoid_: Dry run, Fork test, Simulation

**Release Fingerprint**:
The hash of a contract's code with its immutables masked. It proves which Contract Release is at an address.
_Avoid_: Fingerprint (too vague), Code hash (that is the raw hash)

**Served Chain**:
A chain in a deployment's configured list, checked when wallet-api starts. There is no default chain.
_Avoid_: Supported chain, Enabled chain, Default chain (retired)

### Engineering

**ABIP**:
An Applied Blockchain Improvement Proposal: a company-wide engineering rule that Giano applies, such as ABIP-8 for key generation.
_Avoid_: Policy (too vague), Standard

**Changeset**:
A file under `.changeset/`, made with `pnpm changeset`, that records a version bump and a changelog line. Every change to a published package needs one.
_Avoid_: Changelog entry, Release note

**dApp Fixture**:
The plain test page `e2e/dapp` that the end-to-end tests use as a dApp.
_Avoid_: Test dApp, custom-example (that is the demo)

**Demo Tenants**:
The mock Tenants that show the two ways to integrate. One uses the Stock Wallet: `stock` in the E2E Stack, `example` in `dev`. The other uses wallet-byo as its BYO Wallet: `byo` in the E2E Stack, `byoui` in `dev`. Each Tenant runs custom-example as its dApp in `dev`.
_Avoid_: Test tenants, Fixture tenants, Mock companies

**E2E Stack**:
The Local Stack for end-to-end tests and demos, `deploy/docker-compose.e2e.yml`, with the tests and the apps that run on the host in `e2e/`. It runs two Tenants, `stock` and `byo`, against one wallet-api and two devnet chains.
_Avoid_: Local Stack (any local Compose setup), Stack (that is a set of PRs)

**Local Stack**:
Any Docker Compose setup of Giano on a developer machine or in CI, such as the E2E Stack. Only a Local Stack may load Tenant fixtures.
_Avoid_: Local environment, Stack (that is a set of PRs)

**OpenSpec Change**:
A planned change under `openspec/changes/`, with a proposal, design, specs and tasks. A larger change starts as one before any code.
_Avoid_: Spec (that is `openspec/specs/`), RFC, Proposal (one part of it)

**Stack**:
A chain of pull requests, each built on the one below. `gh stack` manages it, and it merges bottom-up.
_Avoid_: Dependent PRs, PR chain, E2E Stack (the test setup)

**Ticket Code**:
The code of a ticket in the Giano Notion tickets database, such as `G10`. It goes in the PR title.
_Avoid_: Ticket number, Ticket ID

**wallet-byo**:
The reference BYO Wallet, `e2e/wallet-byo`. The BYO Demo Tenant uses it.
_Avoid_: BYO fixture, byoui (that is a Demo Tenant)
