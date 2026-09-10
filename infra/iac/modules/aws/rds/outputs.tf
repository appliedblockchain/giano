output "address" {
  description = "the instance's endpoint hostname"
  value       = aws_db_instance.db.address
}

output "port" {
  description = "the instance's port"
  value       = aws_db_instance.db.port
}

output "arn" {
  description = "ARN of the instance"
  value       = aws_db_instance.db.arn
}

output "identifier" {
  description = "the instance identifier"
  value       = aws_db_instance.db.identifier
}

output "security_group_id" {
  description = "the database's security group"
  value       = aws_security_group.db-sg.id
}
