# §5.2 — public subnets carry only the ALB and the NAT gateways; private subnets carry every
# ECS task and RDS. AZs taken from data.aws_availability_zones.available, never hardcoded.

resource "aws_subnet" "subnet-a-pub" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet-a-pub[terraform.workspace]
  availability_zone = data.aws_availability_zones.available.names[0]

  # nothing is launched into a public subnet that should get an address by default — the ALB
  # and the NATs take theirs explicitly.
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-a-pub" }
}

resource "aws_subnet" "subnet-b-pub" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet-b-pub[terraform.workspace]
  availability_zone = data.aws_availability_zones.available.names[1]

  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-b-pub" }
}

resource "aws_subnet" "subnet-a-priv" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet-a-priv[terraform.workspace]
  availability_zone = data.aws_availability_zones.available.names[0]

  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-a-priv" }
}

resource "aws_subnet" "subnet-b-priv" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet-b-priv[terraform.workspace]
  availability_zone = data.aws_availability_zones.available.names[1]

  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-b-priv" }
}
