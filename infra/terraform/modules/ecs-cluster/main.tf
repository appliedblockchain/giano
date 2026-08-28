# ECS cluster, Cloud Map namespace and the shared task execution role (spec §7.1, §9.2).
#
# The Cloud Map private DNS namespace is what replaces compose's service names: wallet-api
# reaches the bundler at http://bundler.giano-dev.local:4337, and wallet-web's nginx reaches
# the API at http://wallet-api.giano-dev.local:8080. That is why the existing
# GIANO_WALLET_API_UPSTREAM contract needs no change to run on ECS.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name = "containerInsights"
    # "disabled", not "enhanced": /metrics is exposed and nothing scrapes it in dev, and
    # Container Insights would add $10-20/mo of custom metrics nobody reads (decision D12).
    value = var.container_insights ? "enabled" : "disabled"
  }
}

# Fargate only. No EC2 capacity provider, no Spot: task restarts during a working day cost
# more attention than the ~70% saving is worth here (decision D9).
resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 0
  }
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name        = var.service_discovery_namespace
  vpc         = var.vpc_id
  description = "Internal service discovery for ${var.name}"
}

# ── task execution role ────────────────────────────────────────────────────────────────────
#
# Shared by every service: pull images, write logs, read this environment's SSM parameters.
# Scoped by an SSM path prefix rather than by parameter ARN so it does not have to be
# recreated every time a parameter is added.

data "aws_iam_policy_document" "execution_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    # Confused-deputy guard: only this account's ECS tasks may assume it.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-task-execution"
  assume_role_policy = data.aws_iam_policy_document.execution_assume.json
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  statement {
    sid     = "ReadThisEnvironmentsParameters"
    actions = ["ssm:GetParameters", "ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_path_prefix}/*",
    ]
  }

  # SecureStrings under the AWS-managed SSM key need an explicit decrypt grant.
  statement {
    sid       = "DecryptSecureStrings"
    actions   = ["kms:Decrypt"]
    resources = ["arn:aws:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  name   = "read-ssm-parameters"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets.json
}
