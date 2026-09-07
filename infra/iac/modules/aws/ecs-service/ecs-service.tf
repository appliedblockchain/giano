# The task definition, the service and its Cloud Map registration. §9.3
#
# Container definitions are jsonencode(), never a rendered template (D19).
# Every task runs three containers — the application, the Datadog Agent and
# the FireLens router — and wallet-api runs a fourth, the migrate init
# container, which exits before the application starts.

resource "aws_ecs_task_definition" "svc" {
  family = local.name

  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory

  execution_role_arn = module.exec-role.arn
  task_role_arn      = module.task-role.arn

  # ARM64 — cheaper per vCPU-hour, and every image in the repo already builds
  # multi-arch. §9.2
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode(local.container_definitions)

  tags = merge(local.tags, { Name = "${local.name}-task-definition" })
}

resource "aws_ecs_service" "svc" {
  name            = local.name
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.svc.arn
  desired_count   = var.desired_count

  launch_type      = "FARGATE"
  platform_version = "LATEST" # dependsOn needs 1.3.0 or later; LATEST satisfies it

  enable_execute_command = var.enable_execute_command
  wait_for_steady_state  = var.wait_for_steady_state
  propagate_tags         = "SERVICE"

  network_configuration {
    subnets         = var.subnet_ids
    security_groups = var.security_group_ids

    # Always false, no exception, no variable. A task with a public IP is a
    # task the internet can reach if a security group is ever widened by
    # accident. §5.2
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = var.alb_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.svc[0].arn
      container_name   = var.service
      container_port   = var.container_port
    }
  }

  health_check_grace_period_seconds = var.alb_enabled ? var.health_check_grace_period_seconds : null

  service_registries {
    registry_arn = aws_service_discovery_service.svc.arn
  }

  # A bad image rolls back instead of leaving the service cycling — which is
  # also what a failed migration looks like from here (R21).
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = local.deployment_minimum_healthy_percent
  deployment_maximum_percent         = local.deployment_maximum_percent

  tags = merge(local.tags, { Name = local.name })

  lifecycle {
    # The out-of-hours scheduler owns desired_count, so a terraform apply at
    # 20:00 does not silently scale the environment back up. §17.2
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener_rule.svc]
}

# Cloud Map registration, so wallet-api reaches the bundler at
# bundler.giano-dev.local:4337 and wallet-web's nginx reaches the API at
# wallet-api.giano-dev.local:8080. This replaces compose's service names and
# is what lets the existing GIANO_WALLET_API_UPSTREAM contract stay
# unchanged. §9.4
resource "aws_service_discovery_service" "svc" {
  name = var.service

  dns_config {
    namespace_id   = var.service_discovery_namespace_id
    routing_policy = "MULTIVALUE"

    dns_records {
      ttl  = 15
      type = "A"
    }
  }

  # No health_check_custom_config: its only argument, failure_threshold, is
  # deprecated and always 1, and ECS manages registration health itself.

  tags = merge(local.tags, { Name = "${local.name}-discovery" })
}
