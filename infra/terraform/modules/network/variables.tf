variable "name" {
  type        = string
  description = "Resource name prefix, e.g. giano-dev."
}

variable "region" {
  type        = string
  description = "Region, for the S3 gateway endpoint service name."
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR. A /16 leaves room for the /20 subnets this module carves."
  default     = "10.40.0.0/16"
}

variable "container_port" {
  type        = number
  description = "Port every application container listens on. All four web images use 8080."
  default     = 8080
}

variable "bundler_port" {
  type        = number
  description = "Alto's port."
  default     = 4337
}
