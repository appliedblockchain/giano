<<<<<<< HEAD
# aws_secretsmanager_secret + aws_secretsmanager_secret_version, for_each — §7.2
#
# Two rules this module encodes, both of which are the whole point:
#   for_each iterates var.secrets, NEVER var.values — for_each keys must be known at plan
#   time and ephemeral values never are.
#   Rotation is secret_string_wo_version, nothing else — Terraform never reads a write-only
#   value back, so the version number is the only signal that a value changed (§12.6).
=======
# One Secrets Manager secret per key in the 1Password bundle, with the value
# written through a write-only argument so it never reaches state. §7.2
>>>>>>> main

resource "aws_secretsmanager_secret" "secret" {
  for_each = var.secrets

  name                    = "${var.name_prefix}-${each.key}"
  kms_key_id              = var.kms_key_id
  recovery_window_in_days = var.recovery_window_in_days

  tags = merge(local.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_secretsmanager_secret_version" "secret" {
<<<<<<< HEAD
=======
  # for_each iterates var.secrets, NEVER var.values: for_each keys must be
  # known at plan time and ephemeral values never are. Iterating the values
  # map is the single most likely way to break this design, and it fails with
  # a message about unknown keys that does not obviously mean "wrong map".
>>>>>>> main
  for_each = var.secrets

  secret_id = aws_secretsmanager_secret.secret[each.key].id

  # write-only: the value is sent to the API and never persisted to state.
<<<<<<< HEAD
  secret_string_wo         = var.values[each.key]
=======
  secret_string_wo = var.values[each.key]

  # Rotation is this and nothing else. Terraform cannot diff a write-only
  # value — it never reads it back — so the version number is the only signal
  # that a value changed. R6.
>>>>>>> main
  secret_string_wo_version = each.value.version
}
