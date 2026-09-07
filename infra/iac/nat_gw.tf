<<<<<<< HEAD
# §5.4 — two, one per AZ, each in its own public subnet. Two NATs is the shape that carries
# to prd unchanged (D8); one NAT would make an AZ failure in the NAT's own AZ take egress from
# BOTH AZs.

resource "aws_nat_gateway" "natgw-a" {
  subnet_id     = aws_subnet.subnet-a-pub.id
  allocation_id = aws_eip.nat-gw-a-eip.id
  tags          = { Name = "${local.name_prefix}-natgw-a" }
=======
# Two NAT gateways, one per AZ, each in its own public subnet. §5.4
#
# One NAT would be ~$35/mo cheaper and would make an AZ failure in the NAT's
# own AZ take egress from *both* AZs. Two is the shape that carries to prd
# unchanged.

resource "aws_nat_gateway" "natgw-a" {
  subnet_id         = aws_subnet.subnet-a-pub.id
  allocation_id     = aws_eip.nat-gw-a-eip.id
  connectivity_type = var.nat_gateway_connectivity_type

  tags = { Name = "${local.name_prefix}-natgw-a" }
>>>>>>> main

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "natgw-b" {
<<<<<<< HEAD
  subnet_id     = aws_subnet.subnet-b-pub.id
  allocation_id = aws_eip.nat-gw-b-eip.id
  tags          = { Name = "${local.name_prefix}-natgw-b" }
=======
  subnet_id         = aws_subnet.subnet-b-pub.id
  allocation_id     = aws_eip.nat-gw-b-eip.id
  connectivity_type = var.nat_gateway_connectivity_type

  tags = { Name = "${local.name_prefix}-natgw-b" }
>>>>>>> main

  depends_on = [aws_internet_gateway.igw]
}
