# §7.1, §8.2 — TWO customer-managed keys, not one shared key: they protect different things
# with different blast radii, so a grant for either purpose is not a grant for both. Neither
# key can be changed on the resource it encrypts after creation (RDS especially — R12).

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
