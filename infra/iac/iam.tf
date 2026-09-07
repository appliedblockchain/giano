<<<<<<< HEAD
# §10.2, §17.2 — giano-dev-scheduler, the EventBridge Scheduler execution role. Per-service
# execution/task roles are created directly inside modules/aws/ecs-service (§10.1); this file
# is for standalone roles that are not part of an ecs-service instance.

module "iam-role-scheduler" {
  source = "./modules/aws/iam/role"

  name                    = "${local.name_prefix}-scheduler"
  assume_role_policy_json = data.aws_iam_policy_document.scheduler_assume.json
  inline_policy_json      = data.aws_iam_policy_document.scheduler_update_service.json

  additional_tags = local.default_tags
=======
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
>>>>>>> main
}
