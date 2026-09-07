# §11

output "repository_url" {
  description = "repository URL, for docker push/pull and ECS container definitions"
  value       = aws_ecr_repository.repo.repository_url
}

output "repository_arn" {
  description = "repository ARN, for IAM execution-role ECR-pull grants scoped to one repo"
  value       = aws_ecr_repository.repo.arn
}

output "repository_name" {
  description = "repository name"
  value       = aws_ecr_repository.repo.name
}
