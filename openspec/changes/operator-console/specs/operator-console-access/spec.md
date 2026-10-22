## Purpose

Defines how the paymaster console reaches `wallet-api`'s operator tier and who may use it from there: a same-origin proxy that never forwards a browser `Origin`, an Operator area that exists only where that proxy is configured, and wallet sign-in whose session lives only as long as the page and the connected wallet do.

## ADDED Requirements

### Requirement: The console proxies the operator API on its own origin
When `GIANO_WALLET_API_UPSTREAM` is set, the console's container SHALL serve `/api/<path>` by forwarding it to `<upstream>/<path>`, keeping the query string. It SHALL NOT forward the request's `Origin` header. The upstream SHALL be re-resolved at request time through the nameserver the container is given, so an upstream that is unreachable at boot does not stop the container.

When the variable is unset, no `/api/` location SHALL exist, and the container SHALL start exactly as before. The entrypoint SHALL use only `sh`, `envsubst` and `jq`.

#### Scenario: Operator call through the console
- **WHEN** the console page posts to `/api/v1/operator/auth/challenge` on its own origin
- **THEN** `wallet-api` receives the request with no `Origin` header and answers it, rather than refusing it with `403 operator-origin-refused`

#### Scenario: No upstream configured
- **WHEN** the console runs without `GIANO_WALLET_API_UPSTREAM`
- **THEN** `/api/v1/operator/tenants` is served the SPA's `index.html` fallback, not a proxied response, and `config.json` reports `operatorApi: false`

### Requirement: The Operator area exists only where the operator API is reachable
`config.json` SHALL carry `operatorApi`, which is `true` exactly when the upstream is configured. When it is `false`, the console SHALL show no Operator area and no control that leads to one, and the Paymaster tabs SHALL behave as before. When it is `true`, the header SHALL offer a switch between the Paymaster area and the Operator area.

If the upstream is configured but answers `404` on operator sign-in, the Operator area SHALL say that the operator API is disabled on this deployment. That is the case where `OPERATOR_ADDRESSES` is empty.

#### Scenario: Console without operator API
- **WHEN** `operatorApi` is false
- **THEN** the header shows no Operator switch, and the Overview, Tenants, Roles, Settings, History and Health tabs are unchanged

#### Scenario: Operator API disabled on the backend
- **WHEN** `operatorApi` is true and the challenge request returns 404
- **THEN** the Operator area shows that the operator API is disabled on this deployment, and offers no sign-in

### Requirement: Operators sign in with the connected wallet
In the Operator area without a session, the console SHALL show only a sign-in view. *Sign in with wallet* SHALL:
1. connect the wallet if it is not connected, through the existing connect flow;
2. request a challenge for the connected address and the selected deployment's chain;
3. ask the wallet to `personal_sign` the returned message exactly as received;
4. exchange the message and signature for a session.

The console SHALL never build, edit or display-and-reconstruct the message itself. A refused signature in the wallet SHALL return the operator to the sign-in view with no error beyond the refusal. A `401` from verify SHALL say that the connected address is not on this deployment's operator list.

Once signed in, the Operator area SHALL show the operator id, the address, and when the session expires.

#### Scenario: Successful sign-in
- **WHEN** a listed operator clicks *Sign in with wallet* and approves the signature
- **THEN** the Tenants tab opens and the area shows the operator id, the address and the session expiry

#### Scenario: Address not on the list
- **WHEN** the connected address is not in `OPERATOR_ADDRESSES` and signs the message
- **THEN** the console stays on the sign-in view and says the connected address is not on this deployment's operator list

#### Scenario: Signature refused
- **WHEN** the operator rejects the signature request in the wallet
- **THEN** the console stays on the sign-in view and reports nothing as a failure

### Requirement: The operator session lives only in the page
The console SHALL hold the session token in memory only, never in `localStorage`, `sessionStorage`, cookies or the URL. It SHALL send the token as a bearer credential on every operator call and on nothing else. The session SHALL end in the console, returning it to the sign-in view, on any of these:
- a reload;
- a wallet account or chain change;
- switching deployment;
- *Sign out*, which also calls logout on the API;
- any operator call answered `401`.

#### Scenario: Reload
- **WHEN** a signed-in operator reloads the page
- **THEN** the Operator area shows the sign-in view, and no stored copy of the token exists in browser storage

#### Scenario: Deployment switch
- **WHEN** a signed-in operator switches deployment in the header
- **THEN** the Operator area returns to the sign-in view

#### Scenario: Expired session
- **WHEN** an operator call returns 401 because the session expired
- **THEN** the console returns to the sign-in view and says the session ended

#### Scenario: Sign out
- **WHEN** the operator clicks *Sign out*
- **THEN** the console calls logout, forgets the token, and later use of that token is refused by the API
