# §5.7 — one internet-facing ALB, both public subnets. Host-based routing, never path-based:
# path-based would put wallet-api on a different origin from the wallet UI for some requests
# and the same origin for others, and the moment a browser treats one as cross-origin the
# whole session and passkey story acquires a CORS preflight problem.
#
# Target groups and listener rules for each service live inside modules/aws/ecs-service
# (§9.3) — this file holds only the load balancer itself and its two listeners.

resource "aws_lb" "alb" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.subnet-a-pub.id, aws_subnet.subnet-b-pub.id]
  security_groups    = [aws_security_group.alb-sg.id]

  drop_invalid_header_fields = true
  enable_deletion_protection = var.enable_deletion_protection[terraform.workspace]
  idle_timeout               = 60

  tags = { Name = "${local.name_prefix}-alb" }
}

# :80 — a single default action, redirect to HTTPS. No rules, no targets.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = { Name = "${local.name_prefix}-alb-http" }
}

# :443 — HTTPS, default certificate the wildcard, default action a fixed 404. Tenant
# wallet-host certificates attach as additional SNI certificates via
# aws_lb_listener_certificate (acm.tf).
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "404 Not Found"
      status_code  = "404"
    }
  }

  tags = { Name = "${local.name_prefix}-alb-https" }
}
