# One-shot tasks (spec §7.7).
#
# Task definitions with no service attached, run with `aws ecs run-task`. Plain resources
# rather than the ecs-service module: they have no desired count, no target group and no Cloud
# Map entry, so almost nothing in that module would apply.
#
#   aws ecs run-task --cluster giano-dev --task-definition giano-dev-migrate \
#     --launch-type FARGATE --network-configuration "$(terraform output -raw run_task_network_config)"

data "aws_iam_policy_document" "oneshot_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "oneshot_task" {
  name               = "${local.name}-oneshot-task"
  assume_role_policy = data.aws_iam_policy_document.oneshot_assume.json
}

resource "aws_cloudwatch_log_group" "oneshot" {
  name              = "/ecs/${local.name}/oneshot"
  retention_in_days = 7
}

locals {
  oneshot_log_options = {
    "awslogs-group"         = aws_cloudwatch_log_group.oneshot.name
    "awslogs-region"        = var.region
    "awslogs-stream-prefix" = "ecs"
  }
}

# ── migrate ────────────────────────────────────────────────────────────────────────────────
#
# The wallet-api image with a different command. Run BEFORE the services are updated: a rolling
# deploy that starts first gives you a task pool where half the containers see the old schema.
# This is why the wallet-api service sets RUN_MIGRATIONS=false.

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${local.name}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = module.cluster.execution_role_arn
  task_role_arn            = aws_iam_role.oneshot_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "migrate"
    image     = "${module.ecr.repository_urls["wallet-api"]}:${var.image_tag}"
    essential = true
    command   = ["node", "dist/migrate.js"]

    environment = [
      # loadConfig validates the whole environment even for the migration entrypoint, so the
      # chain scalars have to be present and coherent or migrate exits before touching the
      # database.
      { name = "GIANO_DEPLOYMENT_CLASS", value = "testnet" },
      { name = "CHAIN_ID", value = tostring(var.chain_id) },
      { name = "BUNDLER_URL", value = local.internal.bundler },
      { name = "SPONSORSHIP_ENABLED", value = "false" },
    ]

    secrets = [
      { name = "DATABASE_URL", valueFrom = module.rds.database_url_parameter_arn },
      { name = "RPC_URL", valueFrom = local.rpc_url_arn },
      { name = "TENANTS_SEED", valueFrom = aws_ssm_parameter.tenants_seed.arn },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options   = local.oneshot_log_options
    }
  }])
}

# ── sponsorship provisioning ───────────────────────────────────────────────────────────────
#
# BLOCKED until the e2e provisioner is generalised (spec §15.3): it currently hardcodes the e2e
# tenants' admin keys and reads e2e/devnet/addresses.json. The task definition below assumes a
# script driven entirely by environment.
#
# Not optional. Sponsorship rules are per (tenant, chain) and never inherited — a tenant with
# no rules gets no sponsorship, so skipping this produces an environment where every
# transaction is refused, which looks exactly like a bug.

resource "aws_ecs_task_definition" "provision_sponsorship" {
  count = var.sponsorship_enabled ? 1 : 0

  family                   = "${local.name}-provision-sponsorship"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = module.cluster.execution_role_arn
  task_role_arn            = aws_iam_role.oneshot_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "provision-sponsorship"
    image     = "${module.ecr.repository_urls["wallet-api"]}:${var.image_tag}"
    essential = true
    command   = ["node", "dist/provision-sponsorship.js"]

    environment = [
      # Internal, so the rules go in over the Cloud Map address rather than out through the
      # ALB and back.
      { name = "WALLET_API_URL", value = local.internal.wallet_api },
      { name = "TENANT_SLUG", value = var.environment },
      { name = "SPONSOR_CHAIN_IDS", value = tostring(var.chain_id) },
    ]

    secrets = [
      { name = "TENANT_ADMIN_KEY", valueFrom = aws_ssm_parameter.tenant_admin_key.arn },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options   = local.oneshot_log_options
    }
  }])
}
