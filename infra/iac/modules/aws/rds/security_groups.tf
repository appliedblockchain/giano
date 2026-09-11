# the 5432-from-tasks group — §5.6, §8.1. Ingress from the tasks SECURITY GROUP, never from
# the VPC CIDR: a VPC-CIDR rule means anything that ever lands in the VPC can reach the
# database; a security-group rule means only something running as an ECS task can.

resource "aws_security_group" "db-sg" {
  name        = "${var.name_prefix}-${var.component}-db-sg"
  description = "giano ${var.component} db - 5432 from the tasks security group only"
  vpc_id      = var.vpc_id

  tags = merge(local.tags, { Name = "${var.name_prefix}-${var.component}-db-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "db-from-tasks" {
  security_group_id = aws_security_group.db-sg.id

  referenced_security_group_id = var.source_sg_id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"

  tags = { Name = "${var.name_prefix}-${var.component}-db-from-tasks" }
}
