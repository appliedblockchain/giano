# VPC, subnets and security groups (spec §4).
#
# Two AZs because RDS demands a subnet group spanning two and an ALB demands two subnets. In
# practice only one AZ carries running tasks.
#
# No NAT Gateway (decision D8). Tasks sit in PUBLIC subnets with public IPs so they can reach
# ECR, SSM, CloudWatch Logs and the Base Sepolia RPC. They are not exposed: the `tasks` security
# group accepts nothing but the ALB. The alternatives — a NAT Gateway (~$35/mo + data) or three
# interface endpoints (~$24/mo) — both cost more than the ~$3.65/mo per running task that public
# IPv4 addresses do, at this size. Revisit past ~8 services.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # required by the Cloud Map private DNS namespace

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

# ── subnets ────────────────────────────────────────────────────────────────────────────────

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false # set per-task by the ECS service, not by the subnet

  tags = { Name = "${var.name}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 8)
  availability_zone = local.azs[count.index]

  tags = { Name = "${var.name}-private-${local.azs[count.index]}", Tier = "private" }
}

# ── routing ────────────────────────────────────────────────────────────────────────────────

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.name}-public" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# No default route. The private subnets hold RDS, which needs to reach nothing.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-private" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Free, and it keeps ECR layer pulls (which are S3 objects underneath) off the public path.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id, aws_route_table.private.id]

  tags = { Name = "${var.name}-s3" }
}

# ── security groups ────────────────────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Public ingress on 443/80; egress to tasks only."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-alb" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from the internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from the internet, redirected to HTTPS by the listener"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To application containers"
  referenced_security_group_id = aws_security_group.tasks.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "tasks" {
  name        = "${var.name}-tasks"
  description = "Application containers. Ingress from the ALB only; egress anywhere (no NAT)."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-tasks" }
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_alb" {
  security_group_id            = aws_security_group.tasks.id
  description                  = "From the load balancer"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "tasks_all" {
  security_group_id = aws_security_group.tasks.id
  description       = "ECR, SSM, CloudWatch Logs, the chain RPC"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# The bundler has no ALB target group and no public listener (spec §2). Only wallet-api,
# which lives in the `tasks` group, may reach it.
resource "aws_security_group" "bundler" {
  name        = "${var.name}-bundler"
  description = "Alto. Reachable only from application containers; never from the internet."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-bundler" }
}

resource "aws_vpc_security_group_ingress_rule" "bundler_from_tasks" {
  security_group_id            = aws_security_group.bundler.id
  description                  = "JSON-RPC from wallet-api"
  referenced_security_group_id = aws_security_group.tasks.id
  from_port                    = var.bundler_port
  to_port                      = var.bundler_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "bundler_all" {
  security_group_id = aws_security_group.bundler.id
  description       = "Base Sepolia RPC, ECR, logs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "rds" {
  name        = "${var.name}-rds"
  description = "Postgres. Reachable only from application containers. No egress."
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-rds" }
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_tasks" {
  security_group_id            = aws_security_group.rds.id
  description                  = "Postgres from wallet-api"
  referenced_security_group_id = aws_security_group.tasks.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}
