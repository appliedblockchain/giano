# Neither output is sensitive, because neither is a value. There is no output
# that returns one. §7.5

output "secret_arns" {
  description = "{ key => secret ARN } — for ECS `secrets` blocks and IAM policies"
  value       = { for k, s in aws_secretsmanager_secret.secret : k => s.arn }
}

output "secret_names" {
  description = "{ key => secret name }"
  value       = { for k, s in aws_secretsmanager_secret.secret : k => s.name }
}
