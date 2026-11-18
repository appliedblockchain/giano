#!/usr/bin/env bash
# Runs one SQL file against dev's wallet-api database, in a one-off ECS task.
#
#   AWS_PROFILE=<dev profile> deploy/contracts/dev-db-run.sh deploy/contracts/dev-v3-reset.sql
#
# Why a task: dev's RDS instance is private and only the tasks security group reaches it
# (specs/INFRASTRUCTURE.md §3). wallet-api's image has no shell and no psql (a DHI runtime image),
# but it has node and the pg driver, and its task definition already carries DATABASE_URL. So this
# starts the wallet-api task definition once, on the RUN_TASK_NETWORK subnets, with its command
# replaced by a few lines of node that send the file to the database as one simple query (the
# file's own BEGIN/COMMIT make it one transaction). It works with the wallet-api service scaled to
# 0, which is how the Cut-over runbook (TESTNET-ROLLOUT.md) runs it.
#
# Prints what the file SELECTs (the before and after counts), and exits non-zero if the SQL fails;
# a failed run has rolled back. Needs aws, jq and terraform (for the network output), with
# infra/iac's dev workspace selected.
set -euo pipefail

SQL_FILE="${1:?usage: dev-db-run.sh <file.sql>}"
CLUSTER="giano-dev-ecs"
FAMILY="giano-dev-wallet-api"
CONTAINER="wallet-api"
REGION="${AWS_REGION:-eu-west-2}"
LOG_GROUP="/ecs/giano-dev/wallet-api"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

for tool in aws jq terraform; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }; done
[ "$(terraform -chdir="$ROOT/infra/iac" workspace show)" = "dev" ] || { echo "select infra/iac's dev workspace first" >&2; exit 1; }

# The SQL without its comment lines: a container override is limited to 8192 characters.
SQL="$(grep -vE '^[[:space:]]*--' "$SQL_FILE")"
read -r -d '' JS <<'NODE' || true
const { Client } = require("pg");
const client = new Client({ connectionString: process.env.DATABASE_URL });
(async () => {
  await client.connect();
  const results = [].concat(await client.query(process.env.SQL_TO_RUN));
  for (const r of results) if (r.command === "SELECT" && r.rows.length) console.log("ROWS " + JSON.stringify(r.rows));
  await client.end();
  console.log("SQL OK");
})().catch((error) => { console.error("SQL FAILED: " + error.message); process.exit(1); });
NODE

OVERRIDES="$(jq -cn --arg c "$CONTAINER" --arg js "$JS" --arg sql "$SQL" \
  '{containerOverrides: [{name: $c, command: ["node", "-e", $js], environment: [{name: "SQL_TO_RUN", value: $sql}]}]}')"
[ "${#OVERRIDES}" -le 8192 ] || { echo "the overrides are ${#OVERRIDES} characters, over ECS's 8192" >&2; exit 1; }

NETWORK="$(terraform -chdir="$ROOT/infra/iac" output -json RUN_TASK_NETWORK \
  | jq -c '{awsvpcConfiguration: {subnets: .subnets, securityGroups: .security_groups, assignPublicIp: .assign_public_ip}}')"

TASK_ARN="$(aws ecs run-task --region "$REGION" --cluster "$CLUSTER" --launch-type FARGATE \
  --task-definition "$FAMILY" --network-configuration "$NETWORK" --overrides "$OVERRIDES" \
  --query 'tasks[0].taskArn' --output text)"
echo "started $TASK_ARN; waiting for it to stop…"
aws ecs wait tasks-stopped --region "$REGION" --cluster "$CLUSTER" --tasks "$TASK_ARN"

EXIT="$(aws ecs describe-tasks --region "$REGION" --cluster "$CLUSTER" --tasks "$TASK_ARN" \
  --query "tasks[0].containers[?name=='$CONTAINER'].exitCode | [0]" --output text)"
aws logs tail "$LOG_GROUP" --region "$REGION" --since 30m --format short \
  --log-stream-names "ecs/$CONTAINER/${TASK_ARN##*/}" | grep -E 'ROWS|SQL (OK|FAILED)' || true
echo "exit code: $EXIT"
[ "$EXIT" = "0" ]
