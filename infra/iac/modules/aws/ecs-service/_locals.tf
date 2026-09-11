# module tag, the target-group name truncation (§5.7), and the FireLens logConfiguration
# shared by the application and init containers (§17.3.4).

locals {
  tags = merge(var.additional_tags, {
    module = "aws/ecs-service"
  })

  name = "${var.name_prefix}-${var.service}"

  # Target group names are capped at 32 characters by AWS, and <project>-<env>-<service> does
  # not always fit. Deterministic and independent of how long var.project_name happens to be —
  # truncating alone risks two services colliding on the first 32 characters, so the tail is a
  # hash of the full name. §5.7
  tg_name = length(local.name) <= 32 ? local.name : format(
    "%s-%s", substr(local.name, 0, 23), substr(sha256(local.name), 0, 8)
  )

  # the application/init container logConfiguration. With Datadog on, ships via FireLens,
  # never CloudWatch (D20) — the API key is a secretOptions reference, never an inline option.
  # With it off, straight to the (now un-suffixed) CloudWatch group in cloudwatch.tf, which is
  # what makes it safe for the execution role to also lose access to the Datadog secret when
  # datadog_enabled is false — nothing left in the task definition still references it.
  # jsonencode() both branches to a plain string before the conditional, and jsondecode() the
  # result: the two shapes' `options` objects have different keys, and HCL's ternary requires
  # both branches to unify to one type — strings always unify, structurally different objects
  # do not ("Inconsistent conditional result types").
  firelens_log_configuration = jsondecode(var.datadog_enabled ? jsonencode({
    logDriver = "awsfirelens"
    options = {
      Name           = "datadog"
      Host           = "http-intake.logs.${var.datadog_site}"
      TLS            = "on"
      provider       = "ecs"
      dd_service     = var.service
      dd_source      = var.datadog_source
      dd_message_key = "log"
      dd_tags        = "env:${terraform.workspace},project:${var.project_name},service:${var.service}"
    }
    secretOptions = [
      { name = "apikey", valueFrom = var.datadog_api_key_arn },
    ]
    }) : jsonencode({
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.log_router.name
      "awslogs-region"        = var.aws_region
      "awslogs-stream-prefix" = "ecs"
    }
  }))
}
