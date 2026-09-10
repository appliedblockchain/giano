variable "subnet-a-pub" {
  description = "[REQUIRED] public subnet CIDR, AZ a"
  type        = map(string)
  default     = { dev = "10.40.0.0/20", stg = "10.41.0.0/20", prd = "10.42.0.0/20" }
}

variable "subnet-b-pub" {
  description = "[REQUIRED] public subnet CIDR, AZ b"
  type        = map(string)
  default     = { dev = "10.40.16.0/20", stg = "10.41.16.0/20", prd = "10.42.16.0/20" }
}

variable "subnet-a-priv" {
  description = "[REQUIRED] private subnet CIDR, AZ a"
  type        = map(string)
  default     = { dev = "10.40.32.0/20", stg = "10.41.32.0/20", prd = "10.42.32.0/20" }
}

variable "subnet-b-priv" {
  description = "[REQUIRED] private subnet CIDR, AZ b"
  type        = map(string)
  default     = { dev = "10.40.48.0/20", stg = "10.41.48.0/20", prd = "10.42.48.0/20" }
}
