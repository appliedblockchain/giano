variable "log_retention_in_days" {
  description = "[REQUIRED] CloudWatch retention, per environment. Applies to the services' log-router groups and the one-shot task's group"
  type        = map(number)
  default     = { dev = 7, stg = 14, prd = 30 }
}
