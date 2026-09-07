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

# GitHub Actions, the Terraform half. §10.5.1
#
# The trust policy is `gha_deploy_assume` above — same repository, same refs.
# What differs is the PERMISSIONS, and the split is the whole point of having
# a second role: `plan` needs to read everything, `apply` needs to write only
# what a version bump touches. So read comes from AWS's `ReadOnlyAccess`
# (github_oidc.tf) and this document is the write half — ECS, the state
# object, and nothing else.
#
# The consequence is deliberate: CI can roll a new image out and cannot do
# anything else. A merged change that touches the VPC, RDS, DNS or IAM fails
# the apply with an explicit AccessDenied and waits for a human at a
# workstation. That is a narrower blast radius than a broad deploy role, and
# it fails loudly rather than quietly doing the wrong thing.
data "aws_iam_policy_document" "gha_terraform" {
  # `use_lockfile = true` (§4.5) — the lock is an S3 object next to the state,
  # written with a conditional PutObject, so no DynamoDB table and no extra
  # permission beyond the three below.
  statement {
    sid = "TerraformState"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = [
      "arn:aws:s3:::${var.s3_tfstate_name}/env/${terraform.workspace}/*",
    ]
  }

  statement {
    sid       = "TerraformStateBucket"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.s3_tfstate_name}"]
  }

  # The bucket's default encryption is `aws:kms` with the AWS-managed `aws/s3`
  # key (modules/aws/s3/backend). ReadOnlyAccess does not carry kms:Decrypt,
  # and without it the state cannot be read at all — the failure is an opaque
  # `AccessDenied` on the state object rather than on the key.
  statement {
    sid       = "TerraformStateKms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region[terraform.workspace]}.amazonaws.com"]
    }
  }

  # A tag bump is a new task definition and an UpdateService per service.
  # Deregister is included because Terraform revises a task definition in
  # place and cleans up behind itself; without it the apply succeeds and then
  # fails on the destroy half of the plan.
  statement {
    sid = "RollServices"
    actions = [
      "ecs:DescribeServices",
      "ecs:UpdateService",
      "ecs:TagResource",
    ]
    resources = [
      "arn:aws:ecs:${var.aws_region[terraform.workspace]}:${data.aws_caller_identity.current.account_id}:service/${aws_ecs_cluster.ecs.name}/*",
    ]
  }

  statement {
    sid = "TaskDefinitions"
    actions = [
      "ecs:RegisterTaskDefinition",
      "ecs:DeregisterTaskDefinition",
      "ecs:DescribeTaskDefinition",
      "ecs:TagResource",
    ]
    resources = ["*"] # neither Register nor Deregister takes a resource
  }

  # The same scoped list the deploy role gets: the execution and task roles,
  # and nothing else.
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
