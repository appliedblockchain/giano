output "repository_url" {
  description = "the repository URL images are tagged against"
  value       = aws_ecr_repository.repo.repository_url
}

output "repository_arn" {
  description = "ARN of the repository — what an execution role's ECR pull statement is scoped to"
  value       = aws_ecr_repository.repo.arn
}

output "repository_name" {
  description = "name of the repository"
  value       = aws_ecr_repository.repo.name
}
