## ADDED Requirements

### Requirement: Platform admins see sign-ins and sessions
`GET /v1/platform/admins` SHALL return, for each platform admin, the time of their last sign-in, or `null`, and the number of their sessions that are neither expired nor revoked.

`GET /v1/platform/admins/:id/sessions` SHALL return that admin's sessions from the last 30 days, newest first, each with:
- when it started and when it ends;
- whether it was revoked, and when;
- the chain it was signed for;
- the IP address and user agent recorded at sign-in.

It SHALL never return a session token or its hash.

`DELETE /v1/platform/admins/:id/sessions/:sessionId` SHALL end one of the caller's own sessions. Ending another admin's session SHALL return 403; removing the admin is the way to end all of them.

#### Scenario: Last sign-in
- **WHEN** `ops-diogo` signed in yesterday and has no open session
- **THEN** their entry shows yesterday's sign-in and 0 active sessions

#### Scenario: End your own other session
- **WHEN** a platform admin ends another of their own open sessions
- **THEN** that session's next request returns 401, and the caller's current session continues

#### Scenario: Another admin's session
- **WHEN** a platform admin tries to end a session belonging to another admin
- **THEN** the response is 403 and the session continues
