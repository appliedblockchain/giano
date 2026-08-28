# One Fargate service (spec §7).
#
# Five near-identical services differ only in image, size, environment, secrets and whether
# they get an ALB target — which is exactly the shape a module is for. It owns the whole path
# from hostname to container: log group, task definition, service, Cloud Map registration and,
# when `alb_host` is set, its own target group and listener rule.
#
# Set `alb_host = null` for an internal service. The bundler is the one that does: it has no
# public listener and is reachable only from the `tasks` security group.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

locals {
  public = var.alb_host != null
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.cluster_name}/${var.service_name}"
  retention_in_days = var.log_retention_days
}

# ── task role ──────────────────────────────────────────────────────────────────────────────
#
# Deliberately near-empty. Application containers call no AWS API; everything they need comes
# through the execution role at task-start time. The only grant is ECS Exec, and only when
# asked for.

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task" {
  name               = "${var.cluster_name}-${var.service_name}-task"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

# `aws ecs execute-command` into a running task is how a developer reaches the database
# (spec §2 — there is no bastion). It needs these four actions on the task role.
data "aws_iam_policy_document" "exec" {
  count = var.enable_execute_command ? 1 : 0
  statement {
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "exec" {
  count  = var.enable_execute_command ? 1 : 0
  name   = "ecs-exec"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.exec[0].json
}

# ── task definition ────────────────────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "this" {
  family                   = "${var.cluster_name}-${var.service_name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.task.arn

  # ARM64 across the board: cheaper per vCPU-hour, and docker.yml already builds multi-arch.
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    merge(
      {
        name      = var.service_name
        image     = "${var.image_url}:${var.image_tag}"
        essential = true

        portMappings = [{
          containerPort = var.container_port
          protocol      = "tcp"
        }]

        environment = [
          for k, v in var.environment : { name = k, value = tostring(v) }
        ]

        # Never a literal. `valueFrom` is an SSM parameter ARN; the value is fetched by the
        # execution role at task start and never appears in the task definition, in Terraform
        # state, or in the console.
        secrets = [
          for k, v in var.secrets : { name = k, valueFrom = v }
        ]

        logConfiguration = {
          logDriver = "awslogs"
          options = {
            "awslogs-group"         = aws_cloudwatch_log_group.this.name
            "awslogs-region"        = var.region
            "awslogs-stream-prefix" = "ecs"
          }
        }

        # Ordinary containers write nothing to disk; nginx is the exception and gets a tmpfs
        # via its own writable paths, so the root filesystem stays read-only where possible.
        readonlyRootFilesystem = false
      },
      # The images carry their own HEALTHCHECK, but ECS ignores Dockerfile healthchecks — it
      # only honours the one in the task definition. Passing it explicitly is what makes a
      # wedged container get replaced rather than sit there accepting connections.
      var.health_check_command == null ? {} : {
        healthCheck = {
          command     = var.health_check_command
          interval    = 30
          timeout     = 5
          retries     = 3
          startPeriod = var.health_check_start_period
        }
      },
    )
  ])
}

# ── service ────────────────────────────────────────────────────────────────────────────────

resource "aws_ecs_service" "this" {
  name            = var.service_name
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  enable_execute_command = var.enable_execute_command

  # One task, no redundancy (spec §7). 100/0 means a deploy stops the old task before starting
  # the new one — brief downtime, and the only way to roll a single task without paying for a
  # second. Services that matter get 200/100 and a second task.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  health_check_grace_period_seconds = local.public ? var.health_check_grace_period : null

  network_configuration {
    subnets = var.subnet_ids
    # The consequence of having no NAT Gateway (D8). The task needs a route to ECR, SSM and
    # the chain RPC; its security group is what keeps it unreachable.
    assign_public_ip = true
    security_groups  = var.security_group_ids
  }

  service_registries {
    registry_arn = aws_service_discovery_service.this.arn
  }

  dynamic "load_balancer" {
    for_each = local.public ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.this[0].arn
      container_name   = var.service_name
      container_port   = var.container_port
    }
  }

  lifecycle {
    ignore_changes = [
      # The EventBridge scheduler drives this to 0 and back (spec §13). Without this, the next
      # `terraform apply` after 19:00 would helpfully switch the environment back on.
      desired_count,
      # CI owns the deployed revision: it registers a new task definition and calls
      # update-service (spec §10.2). Terraform owns the SHAPE of the task definition and seeds
      # the first revision from var.image_tag. Without this, every apply would roll the
      # services back to whatever tag is in tfvars.
      task_definition,
    ]
  }

  depends_on = [aws_lb_listener_rule.this]
}

resource "aws_service_discovery_service" "this" {
  name = var.service_name

  dns_config {
    namespace_id = var.service_discovery_namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }

  # Health is ECS's business, not Cloud Map's: ECS registers and deregisters the instance as
  # the task starts and stops. An empty custom config is how you say "no Route 53 health
  # check" — `failure_threshold` is deprecated and always 1.
  health_check_custom_config {}

  # Cloud Map refuses to delete a namespace that still has services in it, and it does not
  # always notice the service is gone in time.
  force_destroy = true
}

# ── load balancing (public services only) ──────────────────────────────────────────────────

resource "aws_lb_target_group" "this" {
  count = local.public ? 1 : 0

  name        = substr("${var.cluster_name}-${var.service_name}", 0, 32)
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip" # awsvpc networking registers ENI addresses, not instances

  # 30s, not the 300s default: with one task per service, deregistration delay is dead time on
  # every deploy.
  deregistration_delay = 30

  health_check {
    enabled             = true
    path                = var.health_check_path
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  # No create_before_destroy: the name is static, so a replacement would try to create a
  # second target group with a name the first one still holds, and deadlock. Replacing a
  # target group is disruptive here, which for a single-task dev service is acceptable.
}

resource "aws_lb_listener_rule" "this" {
  count = local.public ? 1 : 0

  listener_arn = var.listener_arn
  priority     = var.listener_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[0].arn
  }

  condition {
    host_header {
      values = [var.alb_host]
    }
  }
}
