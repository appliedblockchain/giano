variable "alb_enable_deletion_protection" {
  description = "[REQUIRED] ALB deletion protection, per environment"
  type        = map(bool)
  default     = { dev = false, stg = true, prd = true }
}

variable "alb_idle_timeout" {
  description = "[REQUIRED] ALB idle timeout, seconds"
  type        = number
  default     = 60
}

variable "alb_ssl_policy" {
  description = "[REQUIRED] TLS policy on the HTTPS listener"
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
