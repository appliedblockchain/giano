output "vpc_id" {
<<<<<<< HEAD
  description = "the VPC id"
=======
  description = "id of the environment's VPC"
>>>>>>> main
  value       = aws_vpc.vpc.id
}

output "vpc_cidr_block" {
<<<<<<< HEAD
  description = "the VPC's CIDR block"
=======
  description = "CIDR network of the environment's VPC"
>>>>>>> main
  value       = aws_vpc.vpc.cidr_block
}
