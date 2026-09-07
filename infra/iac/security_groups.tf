<<<<<<< HEAD
# §5.6 — four security groups, all referencing each other by id rather than by CIDR. No
# 0.0.0.0/0 ingress anywhere except on the ALB. Rules are one resource per rule
# (aws_vpc_security_group_ingress_rule / _egress_rule), not inline ingress {} blocks — an
# inline block is authoritative for the whole group, so a rule added out of band vanishes on
=======
# Four security groups, referencing each other by id rather than by CIDR.
# There is no 0.0.0.0/0 ingress anywhere except on the ALB. §5.6
#
# Rules are one resource each (aws_vpc_security_group_ingress_rule /
# _egress_rule), never inline `ingress {}` blocks: inline blocks are
# authoritative for the whole group, so a rule added out of band vanishes on
>>>>>>> main
# the next apply with no diff that says so.

resource "aws_security_group" "alb-sg" {
  name        = "${local.name_prefix}-alb-sg"
<<<<<<< HEAD
  description = "the ALB - 443 and 80 from the internet"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-alb-sg" }
=======
  description = "${local.name_prefix} ALB — the only internet-facing thing in this account"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-alb-sg" }

  lifecycle { create_before_destroy = true }
>>>>>>> main
}

resource "aws_security_group" "tasks-sg" {
  name        = "${local.name_prefix}-tasks-sg"
<<<<<<< HEAD
  description = "every ECS task - 8080 from the ALB only"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-tasks-sg" }
=======
  description = "${local.name_prefix} ECS tasks — ALB ingress only, egress to the internet through the NATs"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-tasks-sg" }

  lifecycle { create_before_destroy = true }
>>>>>>> main
}

resource "aws_security_group" "bundler-sg" {
  name        = "${local.name_prefix}-bundler-sg"
<<<<<<< HEAD
  description = "the bundler - 4337 from the tasks security group only"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-bundler-sg" }
}

# ── ALB ──────────────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_security_group_ingress_rule" "alb-https" {
  security_group_id = aws_security_group.alb-sg.id
=======
  description = "${local.name_prefix} bundler — no public listener; reachable only from the tasks group"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-bundler-sg" }

  lifecycle { create_before_destroy = true }
}

# --- ALB ------------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "alb-https" {
  security_group_id = aws_security_group.alb-sg.id
  description       = "HTTPS from the internet"
>>>>>>> main
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
<<<<<<< HEAD
  tags              = { Name = "${local.name_prefix}-alb-https-in" }
=======

  tags = { Name = "${local.name_prefix}-alb-sg-in-443" }
>>>>>>> main
}

resource "aws_vpc_security_group_ingress_rule" "alb-http" {
  security_group_id = aws_security_group.alb-sg.id
<<<<<<< HEAD
=======
  description       = "HTTP from the internet — redirected to 443 by the listener"
>>>>>>> main
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
<<<<<<< HEAD
  tags              = { Name = "${local.name_prefix}-alb-http-in" }
=======

  tags = { Name = "${local.name_prefix}-alb-sg-in-80" }
>>>>>>> main
}

resource "aws_vpc_security_group_egress_rule" "alb-to-tasks" {
  security_group_id            = aws_security_group.alb-sg.id
<<<<<<< HEAD
  referenced_security_group_id = aws_security_group.tasks-sg.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  tags                         = { Name = "${local.name_prefix}-alb-to-tasks" }
}

# ── Tasks ────────────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_security_group_ingress_rule" "tasks-from-alb" {
  security_group_id            = aws_security_group.tasks-sg.id
  referenced_security_group_id = aws_security_group.alb-sg.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  tags                         = { Name = "${local.name_prefix}-tasks-from-alb" }
=======
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
>>>>>>> main
}

resource "aws_vpc_security_group_egress_rule" "tasks-egress" {
  security_group_id = aws_security_group.tasks-sg.id
<<<<<<< HEAD
  cidr_ipv4         = "0.0.0.0/0" # ECR, Secrets Manager, CloudWatch, the RPC
  ip_protocol       = "-1"
  tags              = { Name = "${local.name_prefix}-tasks-egress" }
}

# ── Bundler ──────────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_security_group_ingress_rule" "bundler-from-tasks" {
  security_group_id            = aws_security_group.bundler-sg.id
  referenced_security_group_id = aws_security_group.tasks-sg.id
  from_port                    = 4337
  to_port                      = 4337
  ip_protocol                  = "tcp"
  tags                         = { Name = "${local.name_prefix}-bundler-from-tasks" }
=======
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
>>>>>>> main
}

resource "aws_vpc_security_group_egress_rule" "bundler-egress" {
  security_group_id = aws_security_group.bundler-sg.id
<<<<<<< HEAD
  cidr_ipv4         = "0.0.0.0/0" # Base Sepolia RPC
  ip_protocol       = "-1"
  tags              = { Name = "${local.name_prefix}-bundler-egress" }
=======
  description       = "Base Sepolia RPC — out through the NATs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"

  tags = { Name = "${local.name_prefix}-bundler-sg-out-all" }
>>>>>>> main
}
