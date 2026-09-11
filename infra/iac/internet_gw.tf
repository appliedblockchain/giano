# §5.3 — one gateway, serving both directions: inbound for the ALB, outbound for the NATs.
# No second gateway and no egress-only gateway (no IPv6 in this design).

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-igw" }
}
