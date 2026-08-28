# One ALB, host-based routing (spec §5.3).
#
# Four hostnames on one load balancer, because four ALBs would cost ~$54/mo more and buy
# nothing. Target groups and listener rules are NOT here — each ecs-service module creates its
# own against the listener ARN this module outputs, so a service owns its whole path from
# hostname to container.
#
# The default action is an explicit 404 rather than one service quietly absorbing every
# unmatched host.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

resource "aws_lb" "this" {
  name               = var.name
  load_balancer_type = "application"
  internal           = false
  security_groups    = [var.security_group_id]
  subnets            = var.public_subnet_ids

  idle_timeout               = 60
  drop_invalid_header_fields = true
  enable_deletion_protection = var.enable_deletion_protection

  # HTTP/2 to the client; the target connections stay HTTP/1.1, which is what nginx and
  # Fastify are configured for.
  enable_http2 = true
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  # WebAuthn requires a secure context, so there is no case for serving anything on 80.
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "No Giano service is bound to this hostname.\n"
      status_code  = "404"
    }
  }
}
