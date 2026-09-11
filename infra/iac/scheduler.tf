# §17.2 — two EventBridge Scheduler schedules (down at 19:00 UTC, up at 07:00 UTC,
# Mon-Fri — weekends stay down), invoking ecs:UpdateService through giano-dev-scheduler
# against every service. One aws_scheduler_schedule per (service, direction) pair, since each
# schedule resource carries exactly one target — "two schedules" is the two crons, not the AWS
# resource count.
#
# Every service module already carries `lifecycle { ignore_changes = [desired_count] }`
# (§9.3), so a `terraform apply` at 20:00 does not silently scale the environment back up.

resource "aws_scheduler_schedule" "down" {
  for_each = var.enable_schedule[terraform.workspace] ? local.ecs_services : toset([])

  name       = "${local.name_prefix}-${each.key}-down"
  group_name = "default"

  schedule_expression          = "cron(0 19 ? * MON-FRI *)"
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
    role_arn = module.iam-role-scheduler.role_arn

    input = jsonencode({
      Cluster      = aws_ecs_cluster.ecs.name
      Service      = "${local.name_prefix}-${each.key}"
      DesiredCount = 0
    })
  }
}

resource "aws_scheduler_schedule" "up" {
  for_each = var.enable_schedule[terraform.workspace] ? local.ecs_services : toset([])

  name       = "${local.name_prefix}-${each.key}-up"
  group_name = "default"

  schedule_expression          = "cron(0 7 ? * MON-FRI *)"
  schedule_expression_timezone = "UTC"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
    role_arn = module.iam-role-scheduler.role_arn

    input = jsonencode({
      Cluster      = aws_ecs_cluster.ecs.name
      Service      = "${local.name_prefix}-${each.key}"
      DesiredCount = var.ecs_desired_count[terraform.workspace]
    })
  }
}
