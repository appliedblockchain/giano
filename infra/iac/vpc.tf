# One VPC per environment, across two availability zones. §5

resource "aws_vpc" "vpc" {
  cidr_block = var.vpc_cidr[terraform.workspace]

  # Both on: Cloud Map service discovery (§9.4) and the RDS endpoint need them.
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = local.name_prefix }
}
