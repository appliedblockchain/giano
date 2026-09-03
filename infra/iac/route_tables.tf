# One public route table, two private ones. §5.5
#
# The private tables are the reason there are two: each sends 0.0.0.0/0 to the
# NAT in its OWN AZ, so an AZ failure does not take egress from the other AZ.
# Cross-AZ association is the mistake this file exists to prevent — it works,
# costs cross-AZ transfer on every byte of egress, and turns one AZ's NAT into
# a single point of failure for the whole VPC.

resource "aws_route_table" "rt-pub" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${local.name_prefix}-rt-pub" }
}

resource "aws_route_table" "rt-priv-a" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgw-a.id
  }

  tags = { Name = "${local.name_prefix}-rt-priv-a" }
}

resource "aws_route_table" "rt-priv-b" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgw-b.id
  }

  tags = { Name = "${local.name_prefix}-rt-priv-b" }
}

resource "aws_route_table_association" "rt-pub-a" {
  subnet_id      = aws_subnet.subnet-a-pub.id
  route_table_id = aws_route_table.rt-pub.id
}

resource "aws_route_table_association" "rt-pub-b" {
  subnet_id      = aws_subnet.subnet-b-pub.id
  route_table_id = aws_route_table.rt-pub.id
}

resource "aws_route_table_association" "rt-priv-a" {
  subnet_id      = aws_subnet.subnet-a-priv.id
  route_table_id = aws_route_table.rt-priv-a.id
}

resource "aws_route_table_association" "rt-priv-b" {
  subnet_id      = aws_subnet.subnet-b-priv.id
  route_table_id = aws_route_table.rt-priv-b.id
}
