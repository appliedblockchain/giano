locals {
  tags = merge(var.additional_tags, {
    module = "aws/ecr"
  })
}
