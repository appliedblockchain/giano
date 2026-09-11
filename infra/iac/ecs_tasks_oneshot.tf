# §9.7 — one task definition, NO SERVICE ATTACHED, run by hand with `aws ecs run-task` using
# the RUN_TASK_NETWORK output (§4.7). Uses the same execution-role pattern as the services and
# its own task role, in the private subnets with assign_public_ip = false.
#
# `provision-sponsorship` installs a tenant's sponsorship rules through the real admin API.
# Run once at bring-up PER TENANT and whenever the rules change — a tenant with no rules gets
# no sponsorship, which looks exactly like a broken environment. Blocked on §16.3: the image
# does not build `dist/provision-sponsorship.js` as an entry point yet.

data "aws_iam_policy_document" "oneshot_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ecs:${var.aws_region[terraform.workspace]}:${data.aws_caller_identity.current.account_id}:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "oneshot-exec" {
  name               = "${local.name_prefix}-provision-sponsorship-exec"
  assume_role_policy = data.aws_iam_policy_document.oneshot_assume.json

  tags = { Name = "${local.name_prefix}-provision-sponsorship-exec" }
}

data "aws_iam_policy_document" "oneshot_exec" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "EcrPull"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = [module.ecr["wallet-api"].repository_arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.oneshot.arn}:*"]
  }

  statement {
    sid       = "ReadSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [module.asm-app.secret_arns["tenants-seed"]]
  }

  statement {
    sid       = "DecryptSecrets"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.asm-kms-key.arn]
  }
}

resource "aws_iam_role_policy" "oneshot-exec" {
  name   = "${local.name_prefix}-provision-sponsorship-exec"
  role   = aws_iam_role.oneshot-exec.id
  policy = data.aws_iam_policy_document.oneshot_exec.json
}

resource "aws_iam_role" "oneshot-task" {
  name               = "${local.name_prefix}-provision-sponsorship-task"
  assume_role_policy = data.aws_iam_policy_document.oneshot_assume.json

  tags = { Name = "${local.name_prefix}-provision-sponsorship-task" }
}

# plain awslogs, not FireLens — a task that lives forty seconds can exit before Fluent Bit
# has flushed its buffer. §9.5, §9.7
resource "aws_cloudwatch_log_group" "oneshot" {
  name              = "/ecs/${local.name_prefix}/provision-sponsorship"
  retention_in_days = var.log_retention_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-provision-sponsorship-logs" }
}

resource "aws_ecs_task_definition" "provision-sponsorship" {
  family                   = "${local.name_prefix}-provision-sponsorship"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.oneshot-exec.arn
  task_role_arn            = aws_iam_role.oneshot-task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name      = "provision-sponsorship" # the runbook's --overrides addresses it by this name — §18
    image     = "${module.ecr["wallet-api"].repository_url}:${var.image_tag}"
    command   = ["node", "dist/provision-sponsorship.js"] # ⚠ §16.3 — not a build entry yet
    essential = true

    environment = [
      { name = "WALLET_API_URL", value = "http://wallet-api.${local.name_prefix}.local:8080" },
      { name = "CHAIN_ID", value = var.chain_id },
      { name = "SPONSORSHIP_PAYMASTER_ADDRESS", value = var.paymaster_address },
      # TENANT_SLUG is overridden per run — one invocation per tenant, §18 step 8
      { name = "TENANT_SLUG", value = "" },
    ]

    secrets = [
      { name = "TENANTS_SEED", valueFrom = module.asm-app.secret_arns["tenants-seed"] },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.oneshot.name
        "awslogs-region"        = var.aws_region[terraform.workspace]
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Name = "${local.name_prefix}-provision-sponsorship" }
}
