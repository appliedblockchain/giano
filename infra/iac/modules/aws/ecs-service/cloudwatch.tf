# The one CloudWatch group this service keeps. §9.5
#
# With Datadog on, it holds only the log router's own stdout — everything else
# goes straight to the intake. With Datadog off, the application logs here
# instead. Either way it is a Terraform resource rather than left to ECS's
# auto-creation, because an auto-created group has infinite retention and
# nothing ever notices.

resource "aws_cloudwatch_log_group" "svc" {
  name              = var.datadog_enabled ? "/ecs/${var.name_prefix}/${var.service}-log-router" : "/ecs/${var.name_prefix}/${var.service}"
  retention_in_days = var.log_retention_in_days

  tags = merge(local.tags, { Name = "${local.name}-logs" })
}
