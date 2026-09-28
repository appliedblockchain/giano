# With Datadog on, the only CloudWatch group left in the deployment (D20, §9.5) — it holds
# only the log router's own stdout, everything else ships straight to the intake. With Datadog
# off there is no router, so the application logs land here directly instead. A Terraform
# resource rather than left to ECS's auto-creation, because an auto-created group has infinite
# retention and nothing ever notices.

resource "aws_cloudwatch_log_group" "log_router" {
  name              = var.datadog_enabled ? "/ecs/${var.name_prefix}/${var.service}-log-router" : "/ecs/${var.name_prefix}/${var.service}"
  retention_in_days = var.log_retention_in_days

  tags = merge(local.tags, { Name = "${local.name}-logs" })
}
