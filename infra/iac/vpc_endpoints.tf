# An S3 gateway endpoint on both private route tables. §5.5
#
# It is free, and ECR image layers are served from S3 — so it takes the
# largest egress flow in the environment off the NAT's per-GB charge.

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.vpc.id
  service_name      = "com.amazonaws.${var.aws_region[terraform.workspace]}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.rt-priv-a.id,
    aws_route_table.rt-priv-b.id,
  ]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}
