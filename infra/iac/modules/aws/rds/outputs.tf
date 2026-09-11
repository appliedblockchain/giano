output "address" {
  description = "the instance's DNS endpoint (no port)"
  value       = aws_db_instance.db.address
}

output "port" {
  description = "the instance's port — always 5432"
  value       = aws_db_instance.db.port
}

output "identifier" {
  value = aws_db_instance.db.identifier
}

output "db_instance_arn" {
  value = aws_db_instance.db.arn
}

output "security_group_id" {
  description = "the db security group — 5432 from the tasks SG only"
  value       = aws_security_group.db-sg.id
}
