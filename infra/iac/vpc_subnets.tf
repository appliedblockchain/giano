# Four subnets, two per AZ. AZs come from the data source rather than being
# hardcoded. §5.1
#
# Public subnets carry exactly two kinds of thing — the ALB's nodes and the
# NAT gateways — so nothing is launched into them that should get an address
# by default. §5.2

resource "aws_subnet" "subnet-a-pub" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.subnet-a-pub[terraform.workspace]
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-a-pub" }
}

resource "aws_subnet" "subnet-b-pub" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.subnet-b-pub[terraform.workspace]
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-b-pub" }
}

resource "aws_subnet" "subnet-a-priv" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.subnet-a-priv[terraform.workspace]
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-a-priv" }
}

resource "aws_subnet" "subnet-b-priv" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.subnet-b-priv[terraform.workspace]
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-subnet-b-priv" }
}
