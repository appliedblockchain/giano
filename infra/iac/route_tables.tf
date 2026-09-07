# §5.5 — one public route table, two private ones. Each private table sends 0.0.0.0/0 to the
# NAT in its OWN AZ, so an AZ failure does not take egress from the other AZ. Cross-AZ
# association is the mistake this file exists to prevent.

resource "aws_route_table" "rt-pub" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${local.name_prefix}-rt-pub" }
}

resource "aws_route_table_association" "rt-pub-a" {
  subnet_id      = aws_subnet.subnet-a-pub.id
  route_table_id = aws_route_table.rt-pub.id
}

resource "aws_route_table_association" "rt-pub-b" {
  subnet_id      = aws_subnet.subnet-b-pub.id
  route_table_id = aws_route_table.rt-pub.id
}

resource "aws_route_table" "rt-priv-a" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgw-a.id
  }

  tags = { Name = "${local.name_prefix}-rt-priv-a" }
}

resource "aws_route_table_association" "rt-priv-a" {
  subnet_id      = aws_subnet.subnet-a-priv.id
  route_table_id = aws_route_table.rt-priv-a.id
}

resource "aws_route_table" "rt-priv-b" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgw-b.id
  }

  tags = { Name = "${local.name_prefix}-rt-priv-b" }
}

resource "aws_route_table_association" "rt-priv-b" {
  subnet_id      = aws_subnet.subnet-b-priv.id
  route_table_id = aws_route_table.rt-priv-b.id
}

# S3 gateway endpoint associated with both private route tables — free, and it takes ECR
# layer pulls (the largest egress flow) off the NATs' per-GB charge. §5.5, §5
resource "aws_vpc_endpoint_route_table_association" "s3-priv-a" {
  route_table_id  = aws_route_table.rt-priv-a.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_vpc_endpoint_route_table_association" "s3-priv-b" {
  route_table_id  = aws_route_table.rt-priv-b.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}
