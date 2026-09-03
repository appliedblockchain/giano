locals {
  tags = merge(var.additional_tags, {
    module = "aws/s3/backend"
  })
}
