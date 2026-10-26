---
name: dev-logs
description: Read giano dev-environment ECS service logs from CloudWatch (wallet-api, wallet-web, bundler, paymaster-admin, custom-example, the provision-sponsorship one-shot task). Use when debugging the deployed dev environment, when a dev service misbehaves, returns errors or won't start, or when asked to "check the dev logs" / "tail wallet-api on dev".
---

# Reading dev-environment logs

Dev runs on ECS (cluster `giano-dev-ecs`) in `eu-west-2`, and its containers log straight to CloudWatch through the `awslogs` driver (`infra/iac/modules/aws/ecs-service/_locals.tf`).

- **Log group:** `/ecs/giano-dev/<service>`
- **Log stream:** `ecs/<service>/<task-id>`, with one stream per task, so each deploy or restart opens a new one.

| Service | Log group |
|---|---|
| wallet-api | `/ecs/giano-dev/wallet-api` |
| wallet-web | `/ecs/giano-dev/wallet-web` |
| bundler | `/ecs/giano-dev/bundler` |
| paymaster-admin | `/ecs/giano-dev/paymaster-admin` |
| custom-example | `/ecs/giano-dev/custom-example` |
| custom-example-byoui, wallet-byo | `/ecs/giano-dev/<service>` (exist only when `byo_wallet_enabled` is on) |
| provision-sponsorship (one-shot task) | `/ecs/giano-dev/provision-sponsorship` |

Only dev uses this layout. On stg/prd `datadog_enabled` is true, so application logs go to Datadog through a FireLens sidecar. Their `/ecs/giano-<env>/<service>-log-router` groups hold only the router's own output, so look in Datadog instead.

## 1. Find the latest stream

```sh
aws logs describe-log-streams --log-group-name /ecs/giano-dev/wallet-api --region eu-west-2 \
    --order-by LastEventTime --descending \
    --query 'logStreams[*].{Stream:logStreamName,Last:lastEventTimestamp}' --output table
```

The top row belongs to the most recently active task. `Last` is in epoch milliseconds. Compare it with the current time to choose a `--since` window for step 2. If you want only a handful of streams, add `--max-items 5`.

## 2. Tail it

Historical output (the stream has been quiet for a while):

```sh
aws logs tail /ecs/giano-dev/wallet-api --region eu-west-2 \
    --log-stream-names ecs/wallet-api/<task-id> --since 24h
```

Live output:

```sh
aws logs tail /ecs/giano-dev/wallet-api --region eu-west-2 \
    --log-stream-names ecs/wallet-api/<task-id> --follow
```

`aws logs tail` looks back only **10 minutes** by default. A stream whose last event is older than that (for example a wallet-api task with no traffic for 15h) prints nothing without `--since`. Size the window from the `Last` value in step 1.

Tips:
- Leave out `--log-stream-names` to interleave all tasks in the group, which helps when several tasks run or a rolling deploy has just happened.
- Add `--filter-pattern '"ERROR"'` (or any term) to grep on the server side, and `--format short` to drop the stream-name prefix.
- `--follow` never exits. Run it in the background or with a timeout instead of blocking.

## If a step fails

- **Credential or expired-token errors:** the user has to authenticate (`aws login`, or the SSO profile they use). Ask them to run it with `! aws login`; you can't log in for them.
- **No recent streams, or the service isn't running:** the task is probably failing before it logs. Check the ECS service events on cluster `giano-dev-ecs` (`aws ecs describe-services --cluster giano-dev-ecs --services <service> --region eu-west-2 --query 'services[0].events[:10]'`). A pinned image that has expired from ECR is a known cause.
