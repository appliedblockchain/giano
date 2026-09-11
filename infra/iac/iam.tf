# §10.2, §17.2 — giano-dev-scheduler, the EventBridge Scheduler execution role. Per-service
# execution/task roles are created directly inside modules/aws/ecs-service (§10.1); this file
# is for standalone roles that are not part of an ecs-service instance.

module "iam-role-scheduler" {
  source = "./modules/aws/iam/role"

  name                    = "${local.name_prefix}-scheduler"
  assume_role_policy_json = data.aws_iam_policy_document.scheduler_assume.json
  inline_policy_json      = data.aws_iam_policy_document.scheduler_update_service.json

  additional_tags = local.default_tags
}
