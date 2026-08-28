output "address" {
  value = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "identifier" {
  value = aws_db_instance.this.identifier
}

output "database_url_parameter_arn" {
  value       = aws_ssm_parameter.database_url.arn
  description = "Pass to the wallet-api and migrate task definitions as a `secrets` entry."
}

output "database_url_parameter_name" {
  value = aws_ssm_parameter.database_url.name
}
