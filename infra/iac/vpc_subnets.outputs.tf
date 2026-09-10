output "public_subnet_ids" {
  description = "both public subnet ids"
  value       = [aws_subnet.subnet-a-pub.id, aws_subnet.subnet-b-pub.id]
}

output "private_subnet_ids" {
  description = "both private subnet ids — every ECS task and RDS live here"
  value       = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
}
