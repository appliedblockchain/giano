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

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    # Both conditions, not one: aws:SourceAccount alone permits any ECS
    # resource in the account, aws:SourceArn alone is tighter but the pair is
    # what AWS documents and what a reviewer expects to see. §10.3
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
    resources = ["${aws_cloudwatch_log_group.svc.arn}:*"]
  }

  dynamic "statement" {
    for_each = length(local.all_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.all_secret_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.all_secret_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptSecrets"
      actions   = ["kms:Decrypt"]
      resources = [var.asm_kms_key_arn]
    }
  }
}

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
}
