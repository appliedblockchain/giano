<<<<<<< HEAD
# execution role, task role, their policies — §10. Two DISTINCT roles per service: the
# execution role is used by the Fargate agent before the container starts (pulls the image,
# creates the log stream, resolves `secrets`); the task role is used by the application code
# at runtime and is mostly empty. Never collapsed into one — that would hand the application
# permission to re-read its own secrets from Secrets Manager, which it has no reason to do.
=======
# Two distinct roles per service. §10.1
#
# Execution role — used by the FARGATE AGENT, before the container starts: it
# pulls the image, creates the log stream and resolves the `secrets` block.
# The application never uses it.
#
# Task role — used by the APPLICATION at runtime through the SDK's default
# credential chain. Mostly empty here.
#
# The split matters because the two have different lifetimes and different
# blast radii. Collapsing them hands the application permission to re-read —
# and enumerate — its own secrets, which it has no reason to do. Separate
# roles per service, not one shared pair, so "what can this container do" has
# a per-container answer.
>>>>>>> main

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

<<<<<<< HEAD
    # both conditions, not one — the confused-deputy problem (§10.3)
=======
    # Both conditions, not one: aws:SourceAccount alone permits any ECS
    # resource in the account, aws:SourceArn alone is tighter but the pair is
    # what AWS documents and what a reviewer expects to see. §10.3
>>>>>>> main
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ecs:${var.aws_region}:${var.account_id}:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

<<<<<<< HEAD
# ── Execution role ──────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "exec" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json

  tags = merge(local.tags, { Name = "${local.name}-exec" })
}

locals {
  # the exec role reads every secret this service's task definition can reference: its own
  # `secrets` block, the init container's (if any), and the Datadog API key when enabled.
  exec_secret_arns = concat(
    values(var.secret_arns),
    var.init_container == null ? [] : values(var.init_container.secrets),
    var.datadog_enabled ? [var.datadog_api_key_arn] : [],
  )
}

=======
>>>>>>> main
data "aws_iam_policy_document" "exec" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # AWS requires * for this one action
  }

  statement {
    sid = "EcrPull"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = [var.ecr_repository_arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
<<<<<<< HEAD
    resources = ["${aws_cloudwatch_log_group.log_router.arn}:*"]
  }

  dynamic "statement" {
    for_each = length(local.exec_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.exec_secret_arns
=======
    resources = ["${aws_cloudwatch_log_group.svc.arn}:*"]
  }

  dynamic "statement" {
    for_each = length(local.all_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.all_secret_arns
>>>>>>> main
    }
  }

  dynamic "statement" {
<<<<<<< HEAD
    for_each = length(local.exec_secret_arns) > 0 ? [1] : []
=======
    for_each = length(local.all_secret_arns) > 0 ? [1] : []
>>>>>>> main
    content {
      sid       = "DecryptSecrets"
      actions   = ["kms:Decrypt"]
      resources = [var.asm_kms_key_arn]
    }
  }
}

<<<<<<< HEAD
# aws_iam_role_policy carries no `tags` argument — exempt per §4.3.1
resource "aws_iam_role_policy" "exec" {
  name   = "${local.name}-exec"
  role   = aws_iam_role.exec.id
  policy = data.aws_iam_policy_document.exec.json
}

# ── Task role ────────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json

  tags = merge(local.tags, { Name = "${local.name}-task" })
}

# nothing by default. ssmmessages:* for Session Manager only when enable_execute_command —
# §10.2
data "aws_iam_policy_document" "task_execute_command" {
  count = var.enable_execute_command ? 1 : 0

  statement {
    sid = "ExecuteCommand"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task_execute_command" {
  count = var.enable_execute_command ? 1 : 0

  name   = "${local.name}-task-execute-command"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_execute_command[0].json
=======
# Nothing by default. Credentials reach the container through
# AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, which the Fargate agent sets and
# every SDK's default chain reads — there is no static access key anywhere in
# this deployment. The Datadog Agent needs nothing here either: on Fargate it
# reads the unauthenticated task metadata endpoint. §10.2
data "aws_iam_policy_document" "task" {
  dynamic "statement" {
    for_each = var.enable_execute_command ? [1] : []
    content {
      sid = "SessionManager"
      actions = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
      ]
      resources = ["*"]
    }
  }
}

module "exec-role" {
  source = "../iam/role"

  name               = "${local.name}-exec"
  description        = "${local.name} — Fargate agent: image pull, log stream, secret resolution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json

  inline_policies = { "policy" = data.aws_iam_policy_document.exec.json }
  additional_tags = merge(local.tags, { service = var.service })
}

module "task-role" {
  source = "../iam/role"

  name               = "${local.name}-task"
  description        = "${local.name} — the application's own runtime role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json

  # An empty policy document is still a valid document, but attaching one
  # creates a policy that grants nothing and reads as an oversight. Attach it
  # only when execute-command actually needs it.
  inline_policies = var.enable_execute_command ? { "policy" = data.aws_iam_policy_document.task.json } : {}
  additional_tags = merge(local.tags, { service = var.service })
>>>>>>> main
}
