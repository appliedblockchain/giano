# task definition (3 containers), service, service-discovery registration — §9.3, §9.4

locals {
  # ECS's DescribeTaskDefinition ALWAYS echoes these back, whether or not we declare them —
  # they are not optional-and-omittable, they are optional-and-defaulted. Since
  # container_definitions is a single jsonencode()'d string, Terraform's diff on it is a plain
  # text comparison: leaving these out doesn't mean "AWS assumes empty," it means "every future
  # plan shows a spurious replace," forever, even with zero real changes. Merged into every
  # container shape below.
  container_defaults = {
    mountPoints    = []
    volumesFrom    = []
    systemControls = []
    portMappings   = [] # any container that actually listens overrides this in its own block
    environment    = [] # ditto — every container below that has real env vars overrides this
  }

  app_container = merge(local.container_defaults, {
    name      = var.service
    image     = var.image
    essential = true
    memory    = var.app_memory
    cpu       = 0

    # hostPort is REQUIRED here for the same reason as container_defaults above: in awsvpc
    # network mode hostPort must equal containerPort, and ECS's API always returns it
    # explicitly even if we don't send it — omitting it is diff noise, not a no-op.
    portMappings = [
      { containerPort = var.container_port, hostPort = var.container_port, protocol = "tcp" },
    ]

    environment = [for k, v in var.environment : { name = k, value = v }]
    secrets     = [for k, v in var.secret_arns : { name = k, valueFrom = v }]

    # No init container to depend on — wallet-api runs its own migrations on boot,
    # RUN_MIGRATIONS=true, serialised by a Postgres advisory lock (§9.6). log_router only
    # exists when Datadog is on — depending on a container that was never added to
    # container_definitions is a task-placement failure, not a no-op.
    dependsOn = var.datadog_enabled ? [{ containerName = "log_router", condition = "START" }] : []

    logConfiguration = local.firelens_log_configuration
  })

  # datadog_agent_container and firelens_container exist ONLY when Datadog is on. This is the
  # actual toggle — var.datadog_enabled gating the execution role's secret access (iam.tf)
  # without this would leave a still-present datadog-agent container referencing a secret the
  # role can no longer read, which fails at task launch, not at apply.
  container_definitions = concat(
    [local.app_container],
    # slice(), not a ternary between two differently-sized tuple literals: [a, b] and [] infer
    # as distinct fixed-length tuple types and HCL's conditional requires both branches of a
    # ternary to unify to one type ("Inconsistent conditional result types"). slice() keeps one
    # element type and only the length varies, which unifies fine.
    slice([local.datadog_agent_container, local.firelens_container], 0, var.datadog_enabled ? 2 : 0),
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

  lifecycle {
    # var.image_tag comes from local.image_tag at the root (infra/versions.json, §15.1). Every
    # ECR repo is IMMUTABLE and CI only ever pushes the full commit SHA, never "latest" — so a
    # malformed or missing tag here is not a typo that resolves to something wrong, it is an
    # image that can never be pulled, and the failure would otherwise surface as a task stuck
    # in CannotPullContainerError long after `apply` reported success. Fail the plan instead.
    precondition {
      condition     = can(regex("^[0-9a-f]{40}$", var.image_tag))
      error_message = "image_tag must be a full 40-character lowercase commit SHA — set this workspace's entry in infra/versions.json. Got: \"${var.image_tag}\"."
    }
  }
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
}
