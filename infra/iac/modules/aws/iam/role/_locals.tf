locals {
<<<<<<< HEAD
  tags = merge(var.additional_tags, { module = "aws/iam/role" })
=======
  tags = merge(var.additional_tags, {
    module = "aws/iam/role"
  })
>>>>>>> main
}
