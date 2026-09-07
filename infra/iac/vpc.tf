<<<<<<< HEAD
# One VPC, two availability zones — §5

resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr[terraform.workspace]
  enable_dns_hostnames = true # Cloud Map (§9.4) and the RDS endpoint both need it
=======
# One VPC per environment, across two availability zones. §5

resource "aws_vpc" "vpc" {
  cidr_block = var.vpc_cidr[terraform.workspace]

  # Both on: Cloud Map service discovery (§9.4) and the RDS endpoint need them.
  enable_dns_hostnames = true
>>>>>>> main
  enable_dns_support   = true

  tags = { Name = local.name_prefix }
}
