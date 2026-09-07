output "public_subnet_ids" {
<<<<<<< HEAD
  description = "both public subnet ids"
  value       = [aws_subnet.subnet-a-pub.id, aws_subnet.subnet-b-pub.id]
}

output "private_subnet_ids" {
  description = "both private subnet ids — every ECS task and RDS live here"
  value       = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
=======
  description = "the public subnets — ALB nodes and NAT gateways only"
  value       = local.public_subnet_ids
}

output "private_subnet_ids" {
  description = "the private subnets — every ECS task and the RDS instance"
  value       = local.private_subnet_ids
>>>>>>> main
}
