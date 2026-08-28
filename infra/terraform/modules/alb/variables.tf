variable "name" {
  type        = string
  description = "Load balancer name, e.g. giano-dev."
}

variable "security_group_id" {
  type        = string
  description = "The `alb` security group from the network module."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Two public subnets in different AZs."
}

variable "certificate_arn" {
  type        = string
  description = "Validated ACM certificate covering every routed hostname."
}

variable "ssl_policy" {
  type        = string
  description = "TLS policy. The TLS 1.3 policy is safe here: WebAuthn requires a modern browser anyway."
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "enable_deletion_protection" {
  type        = bool
  description = "Off for dev; on for anything with users."
  default     = false
}
