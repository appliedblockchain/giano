# aws_secretsmanager_secret + aws_secretsmanager_secret_version, for_each — §7.2
#
# Two rules this module encodes, both of which are the whole point:
#   for_each iterates var.secrets, NEVER var.values — for_each keys must be known at plan
#   time and ephemeral values never are.
#   Rotation is secret_string_wo_version, nothing else — Terraform never reads a write-only
#   value back, so the version number is the only signal that a value changed (§12.6).

resource "aws_secretsmanager_secret" "secret" {
  for_each = var.secrets

  name                    = "${var.name_prefix}-${each.key}"
  kms_key_id              = var.kms_key_id
  recovery_window_in_days = var.recovery_window_in_days

  tags = merge(local.tags, { Name = "${var.name_prefix}-${each.key}" })
}

resource "aws_secretsmanager_secret_version" "secret" {
  for_each = var.secrets

  secret_id = aws_secretsmanager_secret.secret[each.key].id

  # write-only: the value is sent to the API and never persisted to state.
  secret_string_wo         = var.values[each.key]
  secret_string_wo_version = each.value.version
}
