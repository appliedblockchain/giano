# Target group and listener rule, both gated on var.alb_enabled. §9.3
#
# These live with the service rather than in alb.tf, because the module owns
# the whole path from hostname to container. The bundler passes
# alb_enabled = false, which drops all three of the target group, the rule and
# the load-balancer block on the service.

resource "aws_lb_target_group" "svc" {
  count = var.alb_enabled ? 1 : 0

  # Fargate's awsvpc mode gives each task an ENI and no instance to register.
  # `ip` is required, not preferred. §3.1
  target_type = "ip"

  # Truncated with a hash tail where the full name does not fit in 32
  # characters (§5.7). No `-tg` suffix: the resource type already says what it
  # is, and three characters is a third of the headroom.
  name     = local.tg_name
  port     = var.container_port
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  deregistration_delay = var.deregistration_delay

  health_check {
    path                = var.health_check_path
    matcher             = var.health_check_matcher
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  # The full, readable name survives here even when the resource name is
  # truncated, so a console listing is still legible.
  tags = merge(local.tags, { Name = local.name })

  lifecycle { create_before_destroy = true }
}

resource "aws_lb_listener_rule" "svc" {
  for_each = local.alb_host_chunks

  listener_arn = var.alb_listener_arn
  # for_each map keys are strings; the chunk index is the offset from the
  # service's base priority.
  priority = var.alb_rule_priority + tonumber(each.key)

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.svc[0].arn
  }

  condition {
    host_header {
      values = each.value
    }
  }

  tags = merge(local.tags, { Name = "${local.name}-rule-${each.key}" })
}
