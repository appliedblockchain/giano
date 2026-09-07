# The one-shot task's log group. §9.5
#
# provision-sponsorship uses plain awslogs rather than FireLens: a task that
# lives forty seconds can exit before Fluent Bit has flushed its buffer. The
# migrate init container does not have that problem — it lives inside a
# long-running task whose router stays up after it exits — which is why it
# ships to Datadog like everything else.
#
# Every other log group in this deployment belongs to a service and is created
# by modules/aws/ecs-service.

resource "aws_cloudwatch_log_group" "provision-sponsorship" {
  name              = "/ecs/${local.name_prefix}/provision-sponsorship"
  retention_in_days = var.log_retention_in_days[terraform.workspace]

  tags = { Name = "${local.name_prefix}-provision-sponsorship-logs" }
}
