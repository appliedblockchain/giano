<<<<<<< HEAD
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
=======
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
>>>>>>> main
}
