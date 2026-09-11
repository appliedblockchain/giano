# §5.1

variable "vpc_cidr" {
  description = "VPC CIDR network, per environment"
  type        = map(string)
  default = {
    dev = "10.40.0.0/16"
    stg = "10.41.0.0/16"
    prd = "10.42.0.0/16"
  }
}
