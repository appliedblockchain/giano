# Scheduled scale-to-zero (spec §13).
#
# Two EventBridge schedules per service, calling ecs:UpdateService through the universal
# target. Down at 19:00 UTC on weekdays, up at 07:00 UTC on weekdays; Friday's `down` fires and
# nothing brings it back until Monday.
#
# This is why every ecs-service ignores changes to desired_count: otherwise the next
# `terraform apply` after 19:00 would helpfully switch the environment back on.
#
# RDS is deliberately NOT stopped here. `stop-db-instance` auto-restarts after 7 days, which
# turns a cost optimisation into a resource that comes back at unpredictable times. If the
# extra ~$6/mo matters, add it as a separate, deliberately-flagged schedule.
#
# The visible symptom is a 502 from the ALB outside working hours. Say so in the team channel;
# it is cheaper than the alarm that would explain it.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

locals {
  # One schedule per service per direction.
  schedules = var.enabled ? merge(
    { for s in var.service_names : "${s}-up" => { service = s, count = var.up_desired_count, cron = var.up_cron } },
    { for s in var.service_names : "${s}-down" => { service = s, count = 0, cron = var.down_cron } },
  ) : {}
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "update_service" {
  statement {
    sid       = "ScaleThisClustersServices"
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = ["*"]
    # Scoped by cluster rather than by service ARN, so adding a sixth service does not need an
    # IAM change. It still cannot touch a different cluster.
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.cluster_arn]
    }
  }
}

resource "aws_iam_role_policy" "this" {
  name   = "update-service"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.update_service.json
}

resource "aws_scheduler_schedule" "this" {
  for_each = local.schedules

  name       = "${var.name}-${each.key}"
  group_name = "default"

  schedule_expression          = "cron(${each.value.cron})"
  schedule_expression_timezone = var.timezone

  flexible_time_window {
    # Nothing here is time-critical to the minute, but a fixed window keeps the logs readable.
    mode = "OFF"
  }

  target {
    # The "universal target": call any AWS SDK action without a Lambda in between.
    arn      = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
    role_arn = aws_iam_role.this.arn

    input = jsonencode({
      Cluster      = var.cluster_name
      Service      = each.value.service
      DesiredCount = each.value.count
    })

    retry_policy {
      maximum_retry_attempts = 3
    }
  }
}
