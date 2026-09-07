output "public_subnet_ids" {
  description = "the public subnets — ALB nodes and NAT gateways only"
  value       = local.public_subnet_ids
}

output "private_subnet_ids" {
  description = "the private subnets — every ECS task and the RDS instance"
  value       = local.private_subnet_ids
}
