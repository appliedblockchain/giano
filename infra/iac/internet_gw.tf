# One gateway, serving both directions: inbound for the ALB, outbound for the
# NAT gateways. No egress-only gateway — there is no IPv6 in this design. §5.3

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-igw" }
}
