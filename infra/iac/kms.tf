# Two customer-managed keys, not one shared key. §7.1, §8.2
#
# They protect different things with different blast radii: the ASM key gates
# who can read application credentials, the RDS key gates who can restore a
# snapshot. Sharing one means a grant for either purpose is a grant for both.
#
# Neither carries an explicit key policy, so both take the default — root of
# this account. Decrypt is then granted explicitly, per service, in the
# execution-role policies (§10.2), which is the point of a CMK over
# `aws/secretsmanager`: "who can decrypt this environment's secrets" has an
# answer a reviewer can read.

resource "aws_kms_key" "asm-kms-key" {
  description              = "${local.name_prefix}-asm-kms"
  enable_key_rotation      = true
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  deletion_window_in_days  = 30

  tags = { Name = "${local.name_prefix}-asm-kms" }
}

resource "aws_kms_alias" "asm-kms-key-alias" {
  name          = "alias/${local.name_prefix}-asm-kms"
  target_key_id = aws_kms_key.asm-kms-key.key_id
}

# R12: this key CANNOT be changed after the instance exists. Re-keying means a
# snapshot, a copy under the new key and a restore — an outage and a new
# endpoint. It is created in the same apply as the instance, so there is no
# window in which it can be got wrong quietly.
resource "aws_kms_key" "rds-kms-key" {
  description              = "${local.name_prefix}-rds-kms"
  enable_key_rotation      = true
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  deletion_window_in_days  = 30

  tags = { Name = "${local.name_prefix}-rds-kms" }
}

resource "aws_kms_alias" "rds-kms-key-alias" {
  name          = "alias/${local.name_prefix}-rds-kms"
  target_key_id = aws_kms_key.rds-kms-key.key_id
}
