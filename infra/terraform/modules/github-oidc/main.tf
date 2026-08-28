# GitHub Actions deploy role, via OIDC (spec §9.2, §10.2).
#
# No long-lived AWS access keys anywhere: the workflow exchanges a short-lived GitHub OIDC
# token for this role. The trust policy pins the repository AND the refs allowed to assume it,
# so a pull request from a fork cannot reach it.
#
# What it may do: push to this environment's ECR repositories, register task definitions, run
# the one-shot tasks, and update this cluster's services. Nothing else. In particular it cannot
# touch IAM, RDS, the VPC or Terraform state.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# One OIDC provider per account. If another stack already created it, set create_oidc_provider
# = false and pass the existing ARN.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # GitHub rotates its certificate; AWS validates the OIDC provider against its own trust
  # store for this issuer, so the thumbprint is vestigial. Kept because the API requires it.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

locals {
  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.oidc_provider_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The line that matters. Without a `sub` condition, ANY GitHub repository in the world can
    # assume this role.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for r in var.allowed_refs : "repo:${var.github_repository}:ref:${r}"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "${var.name}-github-deploy"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # this action does not accept a resource
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
    resources = var.ecr_repository_arns
  }

  statement {
    sid = "DescribeAndRegisterTaskDefinitions"
    actions = [
      "ecs:DescribeTaskDefinition",
      "ecs:RegisterTaskDefinition",
      # RegisterTaskDefinition and DescribeTaskDefinition take no resource constraint.
      "ecs:ListTaskDefinitions",
    ]
    resources = ["*"]
  }

  statement {
    sid = "DeployToThisCluster"
    actions = [
      "ecs:UpdateService",
      "ecs:DescribeServices",
      "ecs:RunTask",
      "ecs:StopTask",
      "ecs:DescribeTasks",
      "ecs:ListTasks",
    ]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.cluster_arn]
    }
  }

  # Registering a task definition means naming the roles it runs as, which requires PassRole.
  # Scoped to exactly the roles this environment's tasks use — the classic privilege-escalation
  # hole is a wildcard here.
  statement {
    sid       = "PassTaskRoles"
    actions   = ["iam:PassRole"]
    resources = var.passable_role_arns
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }

  # So the workflow can tail the migrate task's output and fail loudly on a bad migration.
  statement {
    sid     = "ReadDeployLogs"
    actions = ["logs:GetLogEvents", "logs:DescribeLogStreams"]
    resources = [
      "arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.cluster_name}/*",
    ]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
