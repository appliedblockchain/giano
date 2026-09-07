# The two roles that belong to no single service. §10.2
#
# Every service's execution and task roles are created by its own
# modules/aws/ecs-service instance — seven pairs, so "what can this container
# do" has a per-container answer. The GitHub Actions role lives in
# github_oidc.tf with the provider that trusts it.

module "scheduler-role" {
  source = "./modules/aws/iam/role"

  name               = "${local.name_prefix}-scheduler"
  description        = "${local.name_prefix} — EventBridge Scheduler, out-of-hours scale to zero"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json

  inline_policies = { "policy" = data.aws_iam_policy_document.scheduler.json }
}
