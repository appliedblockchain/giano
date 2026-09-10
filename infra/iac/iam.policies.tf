# Every policy in this file is built with data.aws_iam_policy_document. There
# is no templates/ directory and no .json.tpl anywhere in this tree: a
# template is unvalidated string interpolation, where a missing comma or an
# unquoted ARN is a runtime failure with no plan-time signal. D19

# The trust policy for anything that runs as an ECS task, carrying both
# confused-deputy conditions. §10.3
data "aws_iam_policy_document" "ecs_task_assume" {
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

# --- provision-sponsorship ------------------------------------------------
#
# The same shape as a service's execution role: the specific ARN, never *.

data "aws_iam_policy_document" "provision-sponsorship-exec" {
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
    resources = [module.ecr["wallet-api"].repository_arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.provision-sponsorship.arn}:*"]
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

# --- EventBridge Scheduler. §17.2 -----------------------------------------

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    sid     = "UpdateThisClustersServices"
    actions = ["ecs:UpdateService"]

    # This cluster's services only.
    resources = [
      "arn:aws:ecs:${var.aws_region[terraform.workspace]}:${data.aws_caller_identity.current.account_id}:service/${aws_ecs_cluster.ecs.name}/*",
    ]
  }
}

# --- GitHub Actions. §10.5 ------------------------------------------------

data "aws_iam_policy_document" "gha_deploy_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type = "Federated"
      # Built as a string rather than read off the resource: the OIDC provider
      # is account-global, so only one workspace creates it (github_oidc.tf).
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com",
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Pinned to the repository AND the ref. An unpinned
    # `repo:appliedblockchain/giano:*` subject would let a workflow on any
    # branch — including one opened by a fork's pull request — assume this
    # role.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        for r in var.gha_allowed_refs[terraform.workspace] :
        "repo:${var.gha_repository}:ref:refs/heads/${r}"
      ]
    }
  }
}

data "aws_iam_policy_document" "gha_deploy" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [for repo in module.ecr : repo.repository_arn]
  }

  statement {
    sid     = "RollServices"
    actions = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = [
      "arn:aws:ecs:${var.aws_region[terraform.workspace]}:${data.aws_caller_identity.current.account_id}:service/${aws_ecs_cluster.ecs.name}/*",
    ]
  }

  statement {
    sid       = "RegisterTaskDefinitions"
    actions   = ["ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition"]
    resources = ["*"] # RegisterTaskDefinition takes no resource
  }

  # The execution and task roles, and nothing else.
  statement {
    sid       = "PassTaskRoles"
    actions   = ["iam:PassRole"]
    resources = local.gha_passable_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}
