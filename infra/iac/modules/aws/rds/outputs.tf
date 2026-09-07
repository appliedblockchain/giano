output "address" {
<<<<<<< HEAD
  description = "the instance's DNS endpoint (no port)"
=======
  description = "the instance's endpoint hostname"
>>>>>>> main
  value       = aws_db_instance.db.address
}

output "port" {
<<<<<<< HEAD
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
=======
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
>>>>>>> main
  value       = aws_security_group.db-sg.id
}
