# One Elastic IP per NAT gateway. §5.4
#
# These addresses are stable, which is a side benefit worth knowing: they are
# the source addresses an RPC provider or a partner would allowlist.

resource "aws_eip" "nat-gw-a-eip" {
  domain               = "vpc"
  public_ipv4_pool     = "amazon"
  network_border_group = var.aws_region[terraform.workspace]

  tags = { Name = "${local.name_prefix}-nat-gw-a-eip" }
}

resource "aws_eip" "nat-gw-b-eip" {
  domain               = "vpc"
  public_ipv4_pool     = "amazon"
  network_border_group = var.aws_region[terraform.workspace]

  tags = { Name = "${local.name_prefix}-nat-gw-b-eip" }
}
