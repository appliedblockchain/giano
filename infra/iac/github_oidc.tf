# §10.5 — the OIDC provider for token.actions.githubusercontent.com, and one role,
# giano-dev-gha-deploy, trusted by it with a subject condition pinned to the repository AND
# the ref. An unpinned repo:appliedblockchain/giano:* subject would let a workflow on any
# branch — including one opened by a fork's pull request — assume the role.
#
# The OIDC provider itself is a DATA SOURCE, not a resource: AWS allows exactly one
# identity provider per issuer URL per ACCOUNT, so it is account-level shared infrastructure,
# not something any one project owns. If this account already runs other GitHub-Actions-based
# projects, one of them created it already — `terraform destroy` on this workspace must never
# be able to take it away from them. Provisioning it (if it genuinely does not exist yet in a
# fresh account) is a one-off `aws iam create-open-id-connect-provider`, not this Terraform's
# job.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "gha_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        for r in var.gha_allowed_refs[terraform.workspace] :
        "repo:appliedblockchain/giano:ref:refs/heads/${r}"
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
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
    ]
    resources = [for r in module.ecr : r.repository_arn]
  }

  statement {
    sid       = "EcsDeploy"
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = ["arn:aws:ecs:${var.aws_region[terraform.workspace]}:${data.aws_caller_identity.current.account_id}:service/${aws_ecs_cluster.ecs.name}/*"]
  }

  # ecs:RegisterTaskDefinition and ecs:DescribeTaskDefinition support NO resource-level
  # permissions — a task-definition family has no ARN to scope to before it exists. Resource
  # "*" is a limitation of the API, not a shortcut, and it is the one place in this document a
  # policy says "*" for something other than ecr:GetAuthorizationToken. What keeps this from
  # being "register anything" is PassEcsRoles below: a revision is only useful if it can
  # reference an execution role and a task role, and this role may pass only the two belonging
  # to this deployment — a revision naming any other role fails at RegisterTaskDefinition.
  #
  # ecs:DeregisterTaskDefinition is deliberately NOT granted. Old revisions accumulating is
  # untidy and free; a deploy role that can deregister is a deploy role that can break a
  # rollback.
  statement {
    sid       = "EcsTaskDefinition"
    actions   = ["ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition"]
    resources = ["*"]
  }

  # iam:PassRole on the execution and task roles ONLY — no broader grant.
  statement {
    sid     = "PassEcsRoles"
    actions = ["iam:PassRole"]
    resources = concat(
      [module.svc-wallet-api.execution_role_arn, module.svc-wallet-api.task_role_arn],
      [module.svc-wallet-web.execution_role_arn, module.svc-wallet-web.task_role_arn],
      [module.svc-custom-example.execution_role_arn, module.svc-custom-example.task_role_arn],
      [module.svc-paymaster-admin.execution_role_arn, module.svc-paymaster-admin.task_role_arn],
      flatten([for m in module.svc-bundler : [m.execution_role_arn, m.task_role_arn]]),
      length(module.svc-custom-example-byoui) > 0 ? [module.svc-custom-example-byoui[0].execution_role_arn, module.svc-custom-example-byoui[0].task_role_arn] : [],
      length(module.svc-wallet-byo) > 0 ? [module.svc-wallet-byo[0].execution_role_arn, module.svc-wallet-byo[0].task_role_arn] : [],
    )
  }
}

module "iam-role-gha-deploy" {
  source = "./modules/aws/iam/role"

  name                    = "${local.name_prefix}-gha-deploy"
  assume_role_policy_json = data.aws_iam_policy_document.gha_assume.json
  inline_policy_json      = data.aws_iam_policy_document.gha_deploy.json

  additional_tags = local.default_tags
}
