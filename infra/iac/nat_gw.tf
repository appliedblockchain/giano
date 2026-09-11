# §5.4 — two, one per AZ, each in its own public subnet. Two NATs is the shape that carries
# to prd unchanged (D8); one NAT would make an AZ failure in the NAT's own AZ take egress from
# BOTH AZs.

resource "aws_nat_gateway" "natgw-a" {
  subnet_id     = aws_subnet.subnet-a-pub.id
  allocation_id = aws_eip.nat-gw-a-eip.id
  tags          = { Name = "${local.name_prefix}-natgw-a" }

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "natgw-b" {
  subnet_id     = aws_subnet.subnet-b-pub.id
  allocation_id = aws_eip.nat-gw-b-eip.id
  tags          = { Name = "${local.name_prefix}-natgw-b" }

  depends_on = [aws_internet_gateway.igw]
}
