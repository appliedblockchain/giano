variable "name" {
  type        = string
  description = "Resource name prefix, e.g. giano-dev."
}

variable "enabled" {
  type        = bool
  description = "Set false to keep the environment up around the clock — a demo week, say."
  default     = true
}

variable "cluster_name" {
  type = string
}

variable "cluster_arn" {
  type        = string
  description = "Scopes the IAM policy to this cluster's services."
}

variable "service_names" {
  type        = list(string)
  description = "Services to scale. All five, normally."
}

variable "up_cron" {
  type        = string
  description = "EventBridge cron, without the cron() wrapper."
  default     = "0 7 ? * MON-FRI *"
}

variable "down_cron" {
  type    = string
  default = "0 19 ? * MON-FRI *"
}

variable "timezone" {
  type        = string
  description = "UTC keeps the crons honest through BST. Use Europe/London to track local working hours instead."
  default     = "UTC"
}

variable "up_desired_count" {
  type    = number
  default = 1
}
