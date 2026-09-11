output "vpc_id" {
  description = "the VPC id"
  value       = aws_vpc.vpc.id
}

output "vpc_cidr_block" {
  description = "the VPC's CIDR block"
  value       = aws_vpc.vpc.cidr_block
}
