# §5.6 — four security groups, all referencing each other by id rather than by CIDR. No
# 0.0.0.0/0 ingress anywhere except on the ALB. Rules are one resource per rule
# (aws_vpc_security_group_ingress_rule / _egress_rule), not inline ingress {} blocks — an
# inline block is authoritative for the whole group, so a rule added out of band vanishes on
# the next apply with no diff that says so.

resource "aws_security_group" "alb-sg" {
  name        = "${local.name_prefix}-alb-sg"
  description = "the ALB - 443 and 80 from the internet"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-alb-sg" }
}

resource "aws_security_group" "tasks-sg" {
  name        = "${local.name_prefix}-tasks-sg"
  description = "every ECS task - 8080 from the ALB only"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-tasks-sg" }
}

resource "aws_security_group" "bundler-sg" {
  name        = "${local.name_prefix}-bundler-sg"
  description = "the bundler - 4337 from the tasks security group only"
  vpc_id      = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-bundler-sg" }
}

# ── ALB ──────────────────────────────────────────────────────────────────────────────────────
resource "aws_vpc_security_group_ingress_rule" "alb-https" {
  security_group_id = aws_security_group.alb-sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  tags              = { Name = "${local.name_prefix}-alb-https-in" }
}

resource "aws_vpc_security_group_ingress_rule" "alb-http" {
  security_group_id = aws_security_group.alb-sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  tags              = { Name = "${local.name_prefix}-alb-http-in" }
}

resource "aws_vpc_security_group_egress_rule" "alb-to-tasks" {
  security_group_id            = aws_security_group.alb-sg.id
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
}

resource "aws_vpc_security_group_egress_rule" "tasks-egress" {
  security_group_id = aws_security_group.tasks-sg.id
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
}

resource "aws_vpc_security_group_egress_rule" "bundler-egress" {
  security_group_id = aws_security_group.bundler-sg.id
  cidr_ipv4         = "0.0.0.0/0" # Base Sepolia RPC
  ip_protocol       = "-1"
  tags              = { Name = "${local.name_prefix}-bundler-egress" }
}
