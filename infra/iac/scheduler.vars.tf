variable "enable_schedule" {
  description = "[REQUIRED] out-of-hours scale-to-zero, per environment — on in dev, off in stg and prd"
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}

variable "schedule_down_cron" {
  description = "[REQUIRED] when every service goes to desiredCount 0"
  type        = string
  default     = "cron(0 19 ? * MON-FRI *)"
}

variable "schedule_up_cron" {
  description = "[REQUIRED] when every service comes back. Note this also re-runs wallet-api's migrate init container, outside any deploy pipeline (§9.6, R22)"
  type        = string
  default     = "cron(0 7 ? * MON-FRI *)"
}

variable "schedule_timezone" {
  description = "[REQUIRED] timezone the crons are evaluated in"
  type        = string
  default     = "UTC"
}
