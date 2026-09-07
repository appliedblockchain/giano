<<<<<<< HEAD
output "bucket_id" {
  description = "id (name) of the state bucket"
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN of the state bucket"
  value       = aws_s3_bucket.this.arn
}

output "bucket_regional_domain_name" {
  description = "regional domain name of the state bucket"
  value       = aws_s3_bucket.this.bucket_regional_domain_name
=======
output "bucket" {
  description = "name of the state bucket"
  value       = aws_s3_bucket.tfstate.id
}

output "arn" {
  description = "ARN of the state bucket"
  value       = aws_s3_bucket.tfstate.arn
>>>>>>> main
}
