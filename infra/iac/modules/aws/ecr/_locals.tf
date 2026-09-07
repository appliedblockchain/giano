<<<<<<< HEAD
# §4.3.1

locals {
  tags = merge(var.additional_tags, { module = "aws/ecr" })
=======
locals {
  tags = merge(var.additional_tags, {
    module = "aws/ecr"
  })
>>>>>>> main
}
