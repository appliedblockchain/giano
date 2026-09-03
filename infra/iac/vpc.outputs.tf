output "vpc_id" {
  description = "id of the environment's VPC"
  value       = aws_vpc.vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR network of the environment's VPC"
  value       = aws_vpc.vpc.cidr_block
}
