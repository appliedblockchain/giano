<<<<<<< HEAD
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
=======
# The task definition, the service and its Cloud Map registration. §9.3
#
# Container definitions are jsonencode(), never a rendered template (D19).
# Every task runs three containers — the application, the Datadog Agent and
# the FireLens router — and wallet-api runs a fourth, the migrate init
# container, which exits before the application starts.

resource "aws_ecs_task_definition" "svc" {
  family = local.name

>>>>>>> main
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
<<<<<<< HEAD
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    cpu_architecture        = "ARM64" # cheaper per vCPU-hour; every image already builds multi-arch
    operating_system_family = "LINUX"
=======

  execution_role_arn = module.exec-role.arn
  task_role_arn      = module.task-role.arn

  # ARM64 — cheaper per vCPU-hour, and every image in the repo already builds
  # multi-arch. §9.2
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
>>>>>>> main
  }

  container_definitions = jsonencode(local.container_definitions)

<<<<<<< HEAD
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
=======
  tags = merge(local.tags, { Name = "${local.name}-task-definition" })
>>>>>>> main
}

resource "aws_ecs_service" "svc" {
  name            = local.name
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.svc.arn
  desired_count   = var.desired_count
<<<<<<< HEAD
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
=======

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
>>>>>>> main
  }

  dynamic "load_balancer" {
    for_each = var.alb_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.svc[0].arn
      container_name   = var.service
      container_port   = var.container_port
    }
  }

<<<<<<< HEAD
=======
  health_check_grace_period_seconds = var.alb_enabled ? var.health_check_grace_period_seconds : null

>>>>>>> main
  service_registries {
    registry_arn = aws_service_discovery_service.svc.arn
  }

<<<<<<< HEAD
  health_check_grace_period_seconds = var.alb_enabled ? var.health_check_grace_period_seconds : null

  enable_execute_command = var.enable_execute_command

  # Two things outside Terraform legitimately own a field here (§9.3): the out-of-hours
  # scheduler (§17.2) owns desired_count between applies, and CI owns WHICH task definition
  # revision is actually deployed. Terraform still registers a new aws_ecs_task_definition
  # revision whenever its content changes — it just never rolls the service onto it. Moving
  # the service to the latest revision is `aws ecs update-service --task-definition ...`, run
  # by the deploy workflow (§15), not `terraform apply`.
  lifecycle {
    ignore_changes = [desired_count, task_definition]
  }

  tags = merge(local.tags, { Name = local.name })

  # The `load_balancer` block above only creates an implicit dependency on the TARGET GROUP
  # resource, not on the LISTENER RULE that actually associates it with the ALB — nothing in
  # this resource's arguments references aws_lb_listener_rule.svc, so without this Terraform
  # has no graph edge forcing the rule to exist first. ECS's CreateService API validates that
  # the target group already has an associated load balancer, so a race loses with
  # "does not have an associated load balancer". aws_lb_listener_rule.svc has count = 0 when
  # alb_enabled is false (bundler), which depends_on handles fine — zero instances to wait on.
  depends_on = [aws_iam_role_policy.exec, aws_lb_listener_rule.svc]
=======
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
>>>>>>> main
}
