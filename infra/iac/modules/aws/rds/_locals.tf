locals {
  tags = merge(var.additional_tags, {
    module = "aws/rds"
  })

  name = "${var.name_prefix}-${var.component}"

  # Derived, not hardcoded, so a major-version bump does not need two edits.
  parameter_group_family = "postgres${split(".", tostring(var.engine_version))[0]}"
}
