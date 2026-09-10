output "bucket" {
  description = "name of the state bucket"
  value       = aws_s3_bucket.tfstate.id
}

output "arn" {
  description = "ARN of the state bucket"
  value       = aws_s3_bucket.tfstate.arn
}
