<<<<<<< HEAD
# module = "aws/rds" tag, and the parameter-group family derived from the engine version —
# §4.2, §4.3.1, §8.1

=======
>>>>>>> main
locals {
  tags = merge(var.additional_tags, {
    module = "aws/rds"
  })

<<<<<<< HEAD
  # derived, not hardcoded, so a major-version bump does not need two edits.
=======
  name = "${var.name_prefix}-${var.component}"

  # Derived, not hardcoded, so a major-version bump does not need two edits.
>>>>>>> main
  parameter_group_family = "postgres${split(".", tostring(var.engine_version))[0]}"
}
