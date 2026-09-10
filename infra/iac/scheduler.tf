# Out-of-hours scale to zero. D9, §17.2
#
# Two crons, but one schedule per service per direction: the universal
# `ecs:UpdateService` target carries one service in its payload, so "all seven
# services" is seven schedules per direction rather than one.
#
# This roughly halves FARGATE and touches nothing else. The ALB, the NAT
# gateways, RDS and the Elastic IPs run whether or not a task does — which is
# why §17.1 shows $237 and $168 rather than $167 and $89 (R13).
#
# The visible symptom is a 502 from the ALB outside working hours.
# Documenting that in the team channel is cheaper than the alarm that would
# explain it.

locals {
  scheduler_directions = var.enable_schedule[terraform.workspace] ? {
    down = { cron = var.schedule_down_cron, desired_count = 0 }
    up   = { cron = var.schedule_up_cron, desired_count = var.ecs_desired_count[terraform.workspace] }
  } : {}

  # One entry per (service, direction).
  schedules = merge([
    for direction, spec in local.scheduler_directions : {
      for service, _ in local.enabled_ecs_services :
      "${direction}-${service}" => merge(spec, { service = service, direction = direction })
    }
  ]...)
}

resource "aws_scheduler_schedule" "scale" {
  for_each = local.schedules

  name       = "${local.name_prefix}-scale-${each.key}"
  group_name = "default"

  # Weekends stay down: Friday's `down` fires and nothing brings it back until
  # Monday.
  schedule_expression          = each.value.cron
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window { mode = "OFF" }

  target {
    # The universal target: an AWS SDK call rather than a Lambda to maintain.
    arn      = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
    role_arn = module.scheduler-role.arn

    input = jsonencode({
      Cluster      = aws_ecs_cluster.ecs.name
      Service      = "${local.name_prefix}-${each.value.service}"
      DesiredCount = each.value.desired_count
    })

    retry_policy {
      maximum_retry_attempts = 3
    }
  }
}
