output "arn" {
  description = "ARN of the role"
  value       = aws_iam_role.role.arn
}

output "name" {
  description = "name of the role"
  value       = aws_iam_role.role.name
}

output "id" {
  description = "id of the role"
  value       = aws_iam_role.role.id
}
