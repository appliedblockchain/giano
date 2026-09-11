output "asm_kms_key_arn" {
  value = aws_kms_key.asm-kms-key.arn
}

output "rds_kms_key_arn" {
  value = aws_kms_key.rds-kms-key.arn
}
