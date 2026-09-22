---
'@appliedblockchain/giano-wallet-web': patch
---

nginx re-resolves the wallet-api upstream per request instead of pinning the address it saw at
startup. `proxy_pass` named the upstream as a literal, and nginx resolves such a host exactly once,
when it loads the config — so a wallet-api task replaced after this container booted left every
`/api` call answering 502 `connect() failed (113: Host is unreachable)` against a torn-down ENI,
until wallet-web itself was restarted. Under ECS the two services roll in parallel and a wallet-api
ENI changes on every rollout, so this fired whenever wallet-web's task won the start race by the
few seconds it usually does; `/` kept serving from disk, which is also what the ALB health-checks,
so the rollout went green and nothing rolled back.

The upstream now lives in a variable with a `resolver` naming the container's own nameserver, read
from `/etc/resolv.conf` — the VPC resolver under ECS, Docker's embedded DNS under compose — which
is what makes nginx defer the lookup. `/api/` is a regex location now, because a `proxy_pass`
carrying a variable does no automatic URI rewrite; the mapping it produces is unchanged,
`/api/v1/x` → `<upstream>/v1/x`, query string included.
