# Four security groups, referencing each other by id rather than by CIDR.
# There is no 0.0.0.0/0 ingress anywhere except on the ALB. §5.6
#
# Rules are one resource each (aws_vpc_security_group_ingress_rule /
# _egress_rule), never inline `ingress {}` blocks: inline blocks are
# authoritative for the whole group, so a rule added out of band vanishes on
# the next apply with no diff that says so.

resource "aws_security_group" "alb-sg" {
  name        = "${local.name_prefix}-alb-sg"
  description = "${local.name_prefix} ALB — the only internet-facing thing in this account"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-alb-sg" }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "tasks-sg" {
  name        = "${local.name_prefix}-tasks-sg"
  description = "${local.name_prefix} ECS tasks — ALB ingress only, egress to the internet through the NATs"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-tasks-sg" }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "bundler-sg" {
  name        = "${local.name_prefix}-bundler-sg"
  description = "${local.name_prefix} bundler — no public listener; reachable only from the tasks group"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-bundler-sg" }

  lifecycle { create_before_destroy = true }
}

# --- ALB ------------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "alb-https" {
  security_group_id = aws_security_group.alb-sg.id
  description       = "HTTPS from the internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  tags = { Name = "${local.name_prefix}-alb-sg-in-443" }
}

resource "aws_vpc_security_group_ingress_rule" "alb-http" {
  security_group_id = aws_security_group.alb-sg.id
  description       = "HTTP from the internet — redirected to 443 by the listener"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"

  tags = { Name = "${local.name_prefix}-alb-sg-in-80" }
}

resource "aws_vpc_security_group_egress_rule" "alb-to-tasks" {
  security_group_id            = aws_security_group.alb-sg.id
  description                  = "to the tasks group on the container port"
  referenced_security_group_id = aws_security_group.tasks-sg.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"

  tags = { Name = "${local.name_prefix}-alb-sg-out-tasks" }
}

# --- Tasks ----------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "tasks-from-alb" {
  security_group_id            = aws_security_group.tasks-sg.id
  description                  = "container port from the ALB"
  referenced_security_group_id = aws_security_group.alb-sg.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"

  tags = { Name = "${local.name_prefix}-tasks-sg-in-alb" }
}

resource "aws_vpc_security_group_egress_rule" "tasks-egress" {
  security_group_id = aws_security_group.tasks-sg.id
  description       = "ECR, Secrets Manager, CloudWatch, Datadog, the RPC — out through the NATs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = { Name = "${local.name_prefix}-tasks-sg-out-all" }
}

# --- Bundler --------------------------------------------------------------
#
# The bundler has no public listener. wallet-api relays user operations to it
# after the policy check; the wallet origin never talks to it directly. §3.4

resource "aws_vpc_security_group_ingress_rule" "bundler-from-tasks" {
  security_group_id            = aws_security_group.bundler-sg.id
  description                  = "4337 from the tasks group only"
  referenced_security_group_id = aws_security_group.tasks-sg.id
  from_port                    = var.bundler_port
  to_port                      = var.bundler_port
  ip_protocol                  = "tcp"

  tags = { Name = "${local.name_prefix}-bundler-sg-in-tasks" }
}

resource "aws_vpc_security_group_egress_rule" "bundler-egress" {
  security_group_id = aws_security_group.bundler-sg.id
  description       = "Base Sepolia RPC — out through the NATs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = { Name = "${local.name_prefix}-bundler-sg-out-all" }
}
