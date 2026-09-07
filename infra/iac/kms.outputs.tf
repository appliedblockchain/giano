<<<<<<< HEAD
output "asm_kms_key_arn" {
  value = aws_kms_key.asm-kms-key.arn
}

output "rds_kms_key_arn" {
  value = aws_kms_key.rds-kms-key.arn
=======
output "kms_key_arns" {
  description = "the two customer-managed keys, by data domain"
  value = {
    asm = aws_kms_key.asm-kms-key.arn
    rds = aws_kms_key.rds-kms-key.arn
  }
>>>>>>> main
}
