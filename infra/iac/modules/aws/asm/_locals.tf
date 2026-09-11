# module = "aws/asm" tag — §4.2, §4.3.1

locals {
  tags = merge(var.additional_tags, {
    module = "aws/asm"
  })
}
