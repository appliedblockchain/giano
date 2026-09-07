# GitHub Actions, authenticated by OIDC. §10.5
#
# No static credentials anywhere in CI: no access key to rotate, no PAT, and
# no iam:PassRole beyond the task and execution roles.

locals {
  # Exactly the roles CI may hand to ECS. Built from the module outputs so a
  # new service is covered automatically and nothing else ever is.
  gha_passable_role_arns = concat(
    [
      module.svc-wallet-api.exec_role_arn, module.svc-wallet-api.task_role_arn,
      module.svc-wallet-web.exec_role_arn, module.svc-wallet-web.task_role_arn,
      module.svc-custom-example.exec_role_arn, module.svc-custom-example.task_role_arn,
      module.svc-paymaster-admin.exec_role_arn, module.svc-paymaster-admin.task_role_arn,
      module.svc-bundler.exec_role_arn, module.svc-bundler.task_role_arn,
    ],
    var.byo_wallet_enabled[terraform.workspace] ? [
      module.svc-custom-example-byoui[0].exec_role_arn, module.svc-custom-example-byoui[0].task_role_arn,
      module.svc-wallet-byo[0].exec_role_arn, module.svc-wallet-byo[0].task_role_arn,
    ] : [],
  )
}

# The provider is ACCOUNT-GLOBAL, so exactly one workspace creates it and the
# others reference it by ARN (iam.policies.tf). Gated on a boolean map rather
# than a workspace comparison, per §4.1.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.gha_create_oidc_provider[terraform.workspace] ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.gha_oidc_thumbprints

  tags = { Name = "${local.name_prefix}-github-oidc" }
}

module "gha-deploy-role" {
  source = "./modules/aws/iam/role"

  name               = "${local.name_prefix}-gha-deploy"
  description        = "${local.name_prefix} — GitHub Actions: ECR push and service rollout"
  assume_role_policy = data.aws_iam_policy_document.gha_deploy_assume.json

  inline_policies = { "policy" = data.aws_iam_policy_document.gha_deploy.json }

  depends_on = [aws_iam_openid_connect_provider.github]
}

# The Terraform role. §10.5.1
#
# Separate from `gha-deploy` rather than an extension of it, because the two
# jobs have different triggers and different blast radii: `docker.yml` pushes
# images on every main push, `terraform.yml` rolls services out only when
# infra/iac changes. One role for both would give the image build permission
# to change the running services.
#
# `ReadOnlyAccess` is an AWS-managed policy, which §10.2 avoids for TASK roles
# — there the objection is that AmazonECSTaskExecutionRolePolicy grants ECR
# pull and log write account-wide to a running container. This is a read-only
# grant to a CI role that already needs to read every resource in the account
# to produce a plan, and enumerating that by hand would be a list to maintain
# forever that is strictly worse than AWS's.
module "gha-terraform-role" {
  source = "./modules/aws/iam/role"

  name        = "${local.name_prefix}-gha-terraform"
  description = "${local.name_prefix} — GitHub Actions: terraform plan and apply"

  # Same repository, same refs as the deploy role — iam.policies.tf.
  assume_role_policy  = data.aws_iam_policy_document.gha_deploy_assume.json
  inline_policies     = { "policy" = data.aws_iam_policy_document.gha_terraform.json }
  managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]

  depends_on = [aws_iam_openid_connect_provider.github]
}
