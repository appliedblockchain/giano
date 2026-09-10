output "database_url_secret_arn" {
  value = aws_secretsmanager_secret.database-url.arn
}

output "datadog_api_key_secret_arn" {
  value = aws_secretsmanager_secret.datadog-api-key.arn
}

output "app_secret_arns" {
  description = "{ key => secret ARN } for every 1Password-sourced app secret — §7.3"
  value       = module.asm-app.secret_arns
}
