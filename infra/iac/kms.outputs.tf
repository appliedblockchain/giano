output "kms_key_arns" {
  description = "the two customer-managed keys, by data domain"
  value = {
    asm = aws_kms_key.asm-kms-key.arn
    rds = aws_kms_key.rds-kms-key.arn
  }
}
