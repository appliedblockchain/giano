# target group + listener rule, both count-gated on var.alb_enabled — §9.3, §5.7. Every
# target group is target_type = "ip": Fargate's awsvpc mode gives each task an ENI and no
# instance to register.

resource "aws_lb_target_group" "svc" {
  count = var.alb_enabled ? 1 : 0

  name        = local.tg_name
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  deregistration_delay = 30 # the default 300 makes every deploy feel broken

  health_check {
    path                = var.health_check_path
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  # a change to a target group's name forces replacement, and the listener rule still
  # references the old one while the new one is created — §5.7
  lifecycle { create_before_destroy = true }

  tags = merge(local.tags, { Name = local.name }) # the readable name survives here
}

resource "aws_lb_listener_rule" "svc" {
  count = var.alb_enabled ? 1 : 0

  listener_arn = var.alb_listener_arn
  priority     = var.alb_rule_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.svc[0].arn
  }

  condition {
    host_header {
      values = var.alb_host_headers
    }
  }

  tags = { Name = "${local.name}-rule" } # aws_lb_listener_rule carries no tags on some AWS provider versions? kept for consistency — harmless if ignored
}
