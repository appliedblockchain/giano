<<<<<<< HEAD
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
=======
# One internet-facing ALB, host-based routing, in both public subnets. §5.7
#
# Target groups and listener rules do NOT live here: they belong to the
# service that owns the hostname, so modules/aws/ecs-service creates them
# (§9.3). What lives here is the load balancer, its two listeners and the
# tenant wallet certificates attached to the HTTPS listener by SNI.

resource "aws_lb" "alb" {
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  internal           = false

  subnets         = local.public_subnet_ids
  security_groups = [aws_security_group.alb-sg.id]

  drop_invalid_header_fields = true
  enable_deletion_protection = var.alb_enable_deletion_protection[terraform.workspace]
  idle_timeout               = var.alb_idle_timeout
>>>>>>> main

  tags = { Name = "${local.name_prefix}-alb" }
}

<<<<<<< HEAD
# :80 — a single default action, redirect to HTTPS. No rules, no targets.
=======
# :80 — one default action and nothing else. No rules, no targets.
>>>>>>> main
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
<<<<<<< HEAD
=======

>>>>>>> main
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

<<<<<<< HEAD
  tags = { Name = "${local.name_prefix}-alb-http" }
}

# :443 — HTTPS, default certificate the wildcard, default action a fixed 404. Tenant
# wallet-host certificates attach as additional SNI certificates via
# aws_lb_listener_certificate (acm.tf).
=======
  tags = { Name = "${local.name_prefix}-alb-listener-http" }
}

# :443 — the wildcard is the default certificate; tenant wallet hosts attach
# as additional SNI certificates below. The default action is an explicit 404
# rather than one service silently absorbing unmatched hosts.
>>>>>>> main
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
<<<<<<< HEAD
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "404 Not Found"
=======
  ssl_policy        = var.alb_ssl_policy

  # The validation resource, not the certificate: it is what guarantees the
  # certificate is issued before the listener tries to serve it.
  certificate_arn = aws_acm_certificate_validation.main.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not found"
>>>>>>> main
      status_code  = "404"
    }
  }

<<<<<<< HEAD
  tags = { Name = "${local.name_prefix}-alb-https" }
=======
  tags = { Name = "${local.name_prefix}-alb-listener-https" }
}

# A CNAME carries no certificate: the ALB must present one valid for the
# hostname the BROWSER asked for, which for a tenant is the tenant's own. §6.3
resource "aws_lb_listener_certificate" "tenant_wallet" {
  for_each = local.tenant_cert_hosts

  listener_arn    = aws_lb_listener.https.arn
  certificate_arn = aws_acm_certificate.tenant_wallet[each.key].arn

  # A certificate cannot be attached before it is issued. In-zone hosts are
  # validated by Terraform; a host in a tenant's own zone waits on the tenant
  # adding the record ACM asked for (R10) — see acm.tf.
  depends_on = [aws_acm_certificate_validation.tenant_wallet]
>>>>>>> main
}
