output "role_arn" {
  description = "ARN of the created role"
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "name of the created role"
  value       = aws_iam_role.this.name
}

output "role_id" {
  description = "id of the created role"
  value       = aws_iam_role.this.id
}
