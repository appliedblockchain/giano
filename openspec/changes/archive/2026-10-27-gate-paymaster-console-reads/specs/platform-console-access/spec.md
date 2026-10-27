## ADDED Requirements

### Requirement: Chain reads need a platform admin session where the platform API is configured
When `platformApi` is `true`, the console SHALL read the chain only through the platform chain read relay on its own origin, `/api/v1/platform/rpc/<chainId>`, sending the session token as a bearer credential. It SHALL make no chain read before a session exists. When the session ends, it SHALL stop polling and clear every chain value it displays before showing the sign-in view.

Writes are unchanged. They are signed and sent by the connected wallet through the wallet's own network, and authorised on chain by the paymaster's roles.

When `platformApi` is `false`, the console SHALL read through each deployment's `rpcUrl` with no sign-in, as before.

#### Scenario: Anonymous visitor on a hosted console
- **WHEN** someone opens a console whose `platformApi` is true and does not sign in
- **THEN** the page shows the sign-in view, makes no chain read, and shows no tenant, balance, role or history data

#### Scenario: Reads after sign-in
- **WHEN** a listed platform admin signs in on the Paymaster area
- **THEN** the Overview loads, and every chain read the page makes goes to `/api/v1/platform/rpc/<chainId>` with the bearer token

#### Scenario: Session ends while the Overview is open
- **WHEN** a chain read returns 401 because the session expired
- **THEN** polling stops, the displayed chain data is cleared, and the console shows the sign-in view saying the session ended

#### Scenario: Standalone console
- **WHEN** `platformApi` is false
- **THEN** the Paymaster tabs load with no wallet and no sign-in, reading through the deployment's `rpcUrl`

## MODIFIED Requirements

### Requirement: The Platform area exists only where the platform API is reachable
`config.json` SHALL carry `platformApi`, which is `true` exactly when the upstream is configured. When it is `false`, the console SHALL show no Platform area and no control that leads to one, and the Paymaster tabs SHALL behave as before. When it is `true`, the header SHALL offer a switch between the Paymaster area and the Platform area.

If the upstream is configured but answers `404` on platform admin sign-in, the console SHALL say that the platform API is disabled on this deployment, so it can neither manage tenants nor read the chain. It SHALL offer no sign-in in either area. That is the case where the environment has no platform sign-in domain.

#### Scenario: Console without platform API
- **WHEN** `platformApi` is false
- **THEN** the header shows no Platform admin switch, and the Overview, Tenants, Roles, Settings, History and Health tabs are unchanged

#### Scenario: Platform API disabled on the backend
- **WHEN** `platformApi` is true and the challenge request returns 404
- **THEN** both areas show that the platform API is disabled on this deployment, and offer no sign-in

### Requirement: Platform admins sign in with the connected wallet
When `platformApi` is `true` and there is no session, the console SHALL show only a sign-in view, in the Paymaster area and in the Platform area alike. *Sign in with wallet* SHALL:
1. connect the wallet if it is not connected, through the existing connect flow;
2. request a challenge for the connected address and the selected deployment's chain;
3. ask the wallet to `personal_sign` the returned message exactly as received;
4. exchange the message and signature for a session.

The console SHALL never build, edit or display-and-reconstruct the message itself. A refused signature in the wallet SHALL return the platform admin to the sign-in view with no error beyond the refusal. A `401` from verify SHALL say that the connected address is not on this deployment's platform admin list.

Once signed in, the console SHALL stay on the area it was in, and SHALL show the platform admin id, the address, and when the session expires.

#### Scenario: Successful sign-in
- **WHEN** a listed platform admin clicks *Sign in with wallet* in the Platform area and approves the signature
- **THEN** the Tenants tab opens and the console shows the platform admin id, the address and the session expiry

#### Scenario: Successful sign-in from the Paymaster area
- **WHEN** a listed platform admin clicks *Sign in with wallet* in the Paymaster area and approves the signature
- **THEN** the Overview tab loads and the console shows the platform admin id, the address and the session expiry

#### Scenario: Address not on the list
- **WHEN** the connected address is not on this deployment's platform admin list and signs the message
- **THEN** the console stays on the sign-in view and says the connected address is not on this deployment's platform admin list

#### Scenario: Signature refused
- **WHEN** the platform admin rejects the signature request in the wallet
- **THEN** the console stays on the sign-in view and reports nothing as a failure

### Requirement: The platform admin session lives only in the page
The console SHALL hold the session token in memory only, never in `localStorage`, `sessionStorage`, cookies or the URL. It SHALL send the token as a bearer credential on every platform admin call, chain reads through the platform relay included, and on nothing else. One session SHALL serve both the Paymaster and the Platform area, and switching between them SHALL NOT end it. The session SHALL end in the console, returning it to the sign-in view, on any of these:
- a reload;
- a wallet account or chain change;
- switching deployment;
- *Sign out*, which also calls logout on the API;
- any platform admin call answered `401`, a chain read included.

#### Scenario: Reload
- **WHEN** a signed-in platform admin reloads the page
- **THEN** the console shows the sign-in view, and no stored copy of the token exists in browser storage

#### Scenario: Area switch
- **WHEN** a signed-in platform admin switches from the Paymaster area to the Platform area and back
- **THEN** no new signature is requested and both areas keep working

#### Scenario: Deployment switch
- **WHEN** a signed-in platform admin switches deployment in the header
- **THEN** the console returns to the sign-in view

#### Scenario: Expired session
- **WHEN** a platform admin call returns 401 because the session expired
- **THEN** the console returns to the sign-in view and says the session ended

#### Scenario: Sign out
- **WHEN** the platform admin clicks *Sign out*
- **THEN** the console calls logout, forgets the token, and later use of that token is refused by the API
