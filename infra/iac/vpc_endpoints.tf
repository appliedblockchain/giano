# §5.5, §5 — an S3 gateway endpoint (free). ECR image layers are served from S3, so this
# takes the largest egress flow in the environment off the NATs' per-GB charge. Route-table
# associations live in route_tables.tf, next to the tables themselves.

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.${var.aws_region[terraform.workspace]}.s3"

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}
