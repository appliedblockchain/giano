# The Datadog Agent and FireLens container definitions, appended to every task definition —
# §17.3.3. `essential` differs between the two, deliberately: the Agent is false (a monitoring
# failure must not take the application down), the router is true (a task with no logs is not
# a task worth keeping alive, and the failure is otherwise silent).

locals {
  datadog_agent_container = {
    name   = "datadog-agent"
    image  = "public.ecr.aws/datadog/agent:latest"
    cpu    = 0
    memory = 256

    essential = false

    environment = [
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
    name              = "log_router"
    image             = "public.ecr.aws/aws-observability/aws-for-fluent-bit:stable"
    essential         = true
    memoryReservation = 100

    firelensConfiguration = {
      type    = "fluentbit"
      options = { "enable-ecs-log-metadata" = "true" }
    }

    # the one CloudWatch destination left in the deployment — §9.5
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.log_router.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }
}
