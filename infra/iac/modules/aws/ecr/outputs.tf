<<<<<<< HEAD
# §11

output "repository_url" {
  description = "repository URL, for docker push/pull and ECS container definitions"
=======
output "repository_url" {
  description = "the repository URL images are tagged against"
>>>>>>> main
  value       = aws_ecr_repository.repo.repository_url
}

output "repository_arn" {
<<<<<<< HEAD
  description = "repository ARN, for IAM execution-role ECR-pull grants scoped to one repo"
=======
  description = "ARN of the repository — what an execution role's ECR pull statement is scoped to"
>>>>>>> main
  value       = aws_ecr_repository.repo.arn
}

output "repository_name" {
<<<<<<< HEAD
  description = "repository name"
=======
  description = "name of the repository"
>>>>>>> main
  value       = aws_ecr_repository.repo.name
}
