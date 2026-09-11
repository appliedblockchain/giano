# the log router's own log group — the only CloudWatch group left in the deployment (D20, §9.5).
# A Terraform resource rather than left to ECS's auto-creation, because an auto-created group
# has infinite retention and nothing ever notices.

resource "aws_cloudwatch_log_group" "log_router" {
  name              = "/ecs/${var.name_prefix}/${var.service}-log-router"
  retention_in_days = var.log_retention_in_days

  tags = merge(local.tags, { Name = "${local.name}-log-router" })
}
