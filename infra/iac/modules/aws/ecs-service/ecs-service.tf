# task definition (3 or 4 containers), service, service-discovery registration — §9.3, §9.4,
# §9.6

locals {
  app_container = {
    name      = var.service
    image     = var.image
    essential = true
    memory    = var.app_memory
    cpu       = 0

    portMappings = [
      { containerPort = var.container_port, protocol = "tcp" },
    ]

    environment = [for k, v in var.environment : { name = k, value = v }]
    secrets     = [for k, v in var.secret_arns : { name = k, valueFrom = v }]

    # `SUCCESS` is the whole mechanism (§9.6): COMPLETE would accept any exit code, START
    # would not wait at all. dependsOn requires platform version >= 1.3.0, which LATEST
    # satisfies.
    dependsOn = concat(
      [{ containerName = "log_router", condition = "START" }],
      var.init_container == null ? [] : [
        { containerName = var.init_container.name, condition = "SUCCESS" }
      ],
    )

    logConfiguration = local.firelens_log_configuration
  }

  init_container_def = var.init_container == null ? null : {
    name    = var.init_container.name
    image   = var.image # the SAME image as the app — one artefact, two commands
    command = var.init_container.command

    # MANDATORY. An essential container exiting — even with 0 — stops the whole task, so an
    # init container that is essential turns every successful migration into a failed
    # deployment.
    essential = false

    # no hard memory limit: it runs before the application container, so it can use the
    # task's headroom, and its reservation is released the moment it exits.
    memoryReservation = 256

    secrets     = [for k, v in var.init_container.secrets : { name = k, valueFrom = v }]
    environment = [{ name = "LOG_LEVEL", value = "info" }]

    dependsOn        = [{ containerName = "log_router", condition = "START" }]
    logConfiguration = local.firelens_log_configuration
  }

  container_definitions = concat(
    [local.app_container],
    var.init_container == null ? [] : [local.init_container_def],
    [local.datadog_agent_container],
    [local.firelens_container],
  )
}

resource "aws_ecs_task_definition" "svc" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    cpu_architecture        = "ARM64" # cheaper per vCPU-hour; every image already builds multi-arch
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode(local.container_definitions)

  tags = merge(local.tags, { Name = local.name })
}

# Cloud Map — §9.4. `wallet-api` reaches the bundler at
# http://bundler.giano-dev.local:4337, wallet-web's nginx reaches the API at
# http://wallet-api.giano-dev.local:8080.
resource "aws_service_discovery_service" "svc" {
  name = var.service

  dns_config {
    namespace_id = var.service_discovery_id

    dns_records {
      ttl  = 15
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  tags = merge(local.tags, { Name = "${local.name}-cloudmap" })
}

resource "aws_ecs_service" "svc" {
  name            = local.name
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.svc.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # a bad image rolls back instead of leaving the service cycling
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # 100/200 where there is an ALB target; 0/100 for a service with no target and one task
  # (bundler) — §9.3
  deployment_minimum_healthy_percent = var.alb_enabled ? 100 : 0
  deployment_maximum_percent         = var.alb_enabled ? 200 : 100

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = false # always, no exception, no variable — §5.2
  }

  dynamic "load_balancer" {
    for_each = var.alb_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.svc[0].arn
      container_name   = var.service
      container_port   = var.container_port
    }
  }

  service_registries {
    registry_arn = aws_service_discovery_service.svc.arn
  }

  health_check_grace_period_seconds = var.alb_enabled ? var.health_check_grace_period_seconds : null

  enable_execute_command = var.enable_execute_command

  # the out-of-hours scheduler (§17.2) owns desired_count between applies
  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = merge(local.tags, { Name = local.name })

  depends_on = [aws_iam_role_policy.exec]
}
