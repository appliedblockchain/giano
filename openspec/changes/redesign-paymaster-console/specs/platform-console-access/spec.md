## RENAMED Requirements

- FROM: `### Requirement: The Platform area exists only where the platform API is reachable`
- TO: `### Requirement: Platform features exist only where the platform API is reachable`

## MODIFIED Requirements

### Requirement: Platform features exist only where the platform API is reachable
`config.json` SHALL carry `platformApi`, which is `true` exactly when the upstream is configured.

When it is `false`, the console SHALL:
- show no Admins tab;
- show no sign-in;
- show no registry data;
- build the Tenants tab from the on-chain roster alone.

When it is `true`:
- the Tenants tab SHALL join the registry to the roster;
- the Admins tab SHALL be shown.

There is no separate Platform area and no area switch.

If the upstream is configured but answers `404` on platform admin sign-in, the console SHALL say that the platform API is disabled on this deployment, so it can neither manage tenants nor read the chain. It SHALL offer no sign-in. That is the case where the environment has no platform sign-in domain.

#### Scenario: Console without platform API
- **WHEN** `platformApi` is false
- **THEN** the tab bar shows no Admins tab, and the Tenants tab lists the on-chain roster by id

#### Scenario: Platform API disabled on the backend
- **WHEN** `platformApi` is true and the challenge request returns 404
- **THEN** the console shows that the platform API is disabled on this deployment, and offers no sign-in

### Requirement: Platform admins sign in with the connected wallet
When `platformApi` is `true` and there is no session, the console SHALL show only the sign-in page, whichever path was opened. *Sign in with wallet* SHALL:
1. connect the wallet if it is not connected, through the existing connect flow;
2. request a challenge for the connected address and the selected deployment's chain;
3. ask the wallet to `personal_sign` the returned message exactly as received;
4. exchange the message and signature for a session.

The console SHALL never build, edit or display-and-reconstruct the message itself. A refused signature in the wallet SHALL return the platform admin to the sign-in page with no error beyond the refusal. A `401` from verify SHALL say that the connected address is not on this deployment's platform admin list.

Once signed in:
- The console SHALL open the path that was asked for.
- The header SHALL show the platform admin id, the address, and how long the session has left.

#### Scenario: Successful sign-in
- **WHEN** a listed platform admin opens `/tenants`, clicks *Sign in with wallet* and approves the signature
- **THEN** the Tenants tab opens and the header shows the platform admin id, the address and the time left in the session

#### Scenario: Successful sign-in from the Paymaster area
- **WHEN** a listed platform admin opens `/`, signs in and approves the signature
- **THEN** the Overview loads and the header shows the platform admin id, the address and the time left in the session

#### Scenario: Address not on the list
- **WHEN** the connected address is not on this deployment's platform admin list and signs the message
- **THEN** the console stays on the sign-in page and says the connected address is not on this deployment's platform admin list

#### Scenario: Signature refused
- **WHEN** the platform admin rejects the signature request in the wallet
- **THEN** the console stays on the sign-in page and reports nothing as a failure

### Requirement: The platform admin session lives only in the page
The console SHALL hold the session token in memory only, never in `localStorage`, `sessionStorage`, cookies or the URL. It SHALL send the token as a bearer credential on every platform admin call, chain reads through the platform relay included, and on nothing else. One session SHALL serve every tab, and moving between tabs SHALL NOT end it.

Two minutes before the session expires, the console SHALL say so. It SHALL offer:
- *Stay signed in*, which signs a fresh challenge and replaces the session without leaving the page;
- *Sign out*.

The session SHALL end in the console, returning it to the sign-in page, on any of these:
- a reload;
- a wallet account or chain change;
- switching deployment;
- *Sign out*, which also calls logout on the API;
- any platform admin call answered `401`, a chain read included.

#### Scenario: Reload
- **WHEN** a signed-in platform admin reloads the page
- **THEN** the console shows the sign-in page, and no stored copy of the token exists in browser storage

#### Scenario: Area switch
- **WHEN** a signed-in platform admin moves from the Overview to the Tenants tab and back
- **THEN** no new signature is requested and both tabs keep working

#### Scenario: Deployment switch
- **WHEN** a signed-in platform admin switches deployment in the header
- **THEN** the console returns to the sign-in page

#### Scenario: Session about to end
- **WHEN** a session has two minutes left and the platform admin chooses *Stay signed in* and signs
- **THEN** the console holds a new session, the page and any unsaved input stay as they were, and the old token is no longer sent

#### Scenario: Expired session
- **WHEN** a platform admin call returns 401 because the session expired
- **THEN** the console returns to the sign-in page and says the session ended

#### Scenario: Sign out
- **WHEN** the platform admin clicks *Sign out*
- **THEN** the console calls logout, forgets the token, and later use of that token is refused by the API

### Requirement: Chain reads need a platform admin session where the platform API is configured
When `platformApi` is `true`, the console SHALL read the chain only through the platform chain read relay on its own origin, `/api/v1/platform/rpc/<chainId>`, sending the session token as a bearer credential. It SHALL make no chain read before a session exists. When the session ends, it SHALL stop polling and clear every chain value it displays before showing the sign-in page.

Writes are unchanged. They are signed and sent by the connected wallet through the wallet's own network, and authorised on chain by the paymaster's roles.

When `platformApi` is `false`, the console SHALL read through each deployment's `rpcUrl` with no sign-in, as before.

#### Scenario: Anonymous visitor on a hosted console
- **WHEN** someone opens a console whose `platformApi` is true and does not sign in
- **THEN** the page shows the sign-in page, makes no chain read, and shows no tenant, balance, role or history data

#### Scenario: Reads after sign-in
- **WHEN** a listed platform admin signs in from `/`
- **THEN** the Overview loads, and every chain read the page makes goes to `/api/v1/platform/rpc/<chainId>` with the bearer token

#### Scenario: Session ends while the Overview is open
- **WHEN** a chain read returns 401 because the session expired
- **THEN** polling stops, the displayed chain data is cleared, and the console shows the sign-in page saying the session ended

#### Scenario: Standalone console
- **WHEN** `platformApi` is false
- **THEN** every tab but Admins loads with no wallet and no sign-in, reading through the deployment's `rpcUrl`
