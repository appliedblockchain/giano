# execution role, task role, their policies — §10. Two DISTINCT roles per service: the
# execution role is used by the Fargate agent before the container starts (pulls the image,
# creates the log stream, resolves `secrets`); the task role is used by the application code
# at runtime and is mostly empty. Never collapsed into one — that would hand the application
# permission to re-read its own secrets from Secrets Manager, which it has no reason to do.

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    # both conditions, not one — the confused-deputy problem (§10.3)
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
    resources = ["${aws_cloudwatch_log_group.log_router.arn}:*"]
  }

  dynamic "statement" {
    for_each = length(local.exec_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.exec_secret_arns
    }
  }

  dynamic "statement" {
    for_each = length(local.exec_secret_arns) > 0 ? [1] : []
    content {
      sid       = "DecryptSecrets"
      actions   = ["kms:Decrypt"]
      resources = [var.asm_kms_key_arn]
    }
  }
}

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
}
