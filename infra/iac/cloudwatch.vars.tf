<<<<<<< HEAD
# No new variables here — log_retention_in_days (ecs_services.vars.tf) already covers every
# CloudWatch group this deployment creates (the log routers' own stdout, D20, plus the
# provision-sponsorship one-shot task's plain awslogs group, §9.5, §9.7).
=======
variable "log_retention_in_days" {
  description = "[REQUIRED] CloudWatch retention, per environment. Applies to the services' log-router groups and the one-shot task's group"
  type        = map(number)
  default     = { dev = 7, stg = 14, prd = 30 }
}
>>>>>>> main
