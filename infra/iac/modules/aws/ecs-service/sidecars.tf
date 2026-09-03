# The Datadog Agent and the FireLens log router. §17.3.3
#
# Both are built here and appended to every task definition's
# container_definitions, so no service can be created without them.
#
# On EC2 or EKS the Agent runs once per host and discovers every container on
# it. Fargate has no host you can put anything on, so the only place an Agent
# can run is inside the task — every task definition carries its own. DD_TAGS
# uses SPACE separators; the FireLens dd_tags option below uses COMMAS. They
# are different parsers.

locals {
  datadog_agent_container = {
    name   = "datadog-agent"
    image  = var.datadog_agent_image
    cpu    = 0
    memory = 256

    # NOT essential, and this is the only interesting decision here.
    # Datadog's own example sets it true; we differ because essential = true
    # means a MONITORING failure takes the application down — an Agent OOM
    # would stop wallet-api and hand a 502 to every tenant. The gap it leaves
    # is closed by two monitors that do not depend on the Agent (§17.3.5), not
    # by trading availability for telemetry. R17
    essential = false

    environment = [
      # DD_HOSTNAME is deliberately absent: there is no host, and setting it
      # invents one that will collide across tasks.
      { name = "ECS_FARGATE", value = "true" },
      { name = "DD_SITE", value = var.datadog_site },
      { name = "DD_APM_ENABLED", value = "true" },
      { name = "DD_DOGSTATSD_NON_LOCAL_TRAFFIC", value = "true" },
      { name = "DD_ENV", value = terraform.workspace },
      { name = "DD_SERVICE", value = var.service },
      { name = "DD_VERSION", value = var.image_tag },
      { name = "DD_TAGS", value = "env:${terraform.workspace} project:${var.project_name} service:${var.service}" },
    ]

    secrets = [
      { name = "DD_API_KEY", valueFrom = var.datadog_api_key_arn },
    ]

    healthCheck = {
      command     = ["CMD-SHELL", "agent health"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 15
    }
  }

  firelens_container = {
    name  = "log_router"
    image = var.firelens_image

    # Essential, for the opposite reason to the Agent: FireLens rewrites the
    # application's stdout through the router, so if the router is gone the
    # logs go nowhere and the Docker log driver can back-pressure a writing
    # process. A task with no logs is not a task worth keeping alive, and
    # unlike telemetry the failure is silent.
    essential         = true
    memoryReservation = 100

    firelensConfiguration = {
      type    = "fluentbit"
      options = { "enable-ecs-log-metadata" = "true" }
    }

    # The one CloudWatch destination left in the deployment: if the router
    # cannot reach Datadog, its own stdout is the only place that says so —
    # and a router that logged to itself would have nowhere to report its own
    # failure. §9.5
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.svc.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }

  # The application container's own logConfiguration — the stock inline-options
  # form, no custom Fluent Bit config file to maintain. D20, §17.3.4
  # tomap() on both option sets, and secretOptions present in both: the two
  # objects are selected by one conditional below, and Terraform unifies the
  # branches of a conditional — which it cannot do for two objects whose
  # attribute names differ.
  firelens_log_configuration = {
    logDriver = "awsfirelens"
    options = tomap({
      Name           = "datadog"
      Host           = "http-intake.logs.${var.datadog_site}"
      TLS            = "on"
      provider       = "ecs"
      dd_service     = var.service
      dd_source      = var.datadog_source
      dd_message_key = "log"
      dd_tags        = "env:${terraform.workspace},project:${var.project_name},service:${var.service}"
    })

    # The API key is NEVER an inline option — it would be readable in the task
    # definition, which is not a secret store.
    secretOptions = [
      { name = "apikey", valueFrom = var.datadog_api_key_arn },
    ]
  }

  awslogs_log_configuration = {
    logDriver = "awslogs"
    options = tomap({
      "awslogs-group"         = aws_cloudwatch_log_group.svc.name
      "awslogs-region"        = var.aws_region
      "awslogs-stream-prefix" = "ecs"
    })
    secretOptions = []
  }

  app_log_configuration = var.datadog_enabled ? local.firelens_log_configuration : local.awslogs_log_configuration
}
