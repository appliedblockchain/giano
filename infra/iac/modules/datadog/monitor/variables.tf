variable "name" {
  description = "[REQUIRED] monitor name, as it appears in Datadog and in the alert"
  type        = string
}

variable "query" {
  description = "[REQUIRED] the monitor query"
  type        = string
}

variable "type" {
  description = "[OPTIONAL] monitor type"
  type        = string
  default     = "metric alert"
}

variable "message" {
  description = "[OPTIONAL] body of the alert. Notifier handles are appended automatically"
  type        = string
  default     = ""
}

variable "monitor_thresholds" {
  description = "[OPTIONAL] { critical, warning } — critical is required by Datadog for a metric alert"
  type = object({
    critical = optional(number)
    warning  = optional(number)
  })
  default = {}
}

variable "notify_no_data" {
  description = "[OPTIONAL] alert when the query stops returning data. The whole mechanism of the Agent-liveness monitor (R17)"
  type        = bool
  default     = false
}

variable "no_data_timeframe" {
  description = "[OPTIONAL] minutes of silence before a no-data alert"
  type        = number
  default     = null
}

variable "evaluation_delay" {
  description = "[OPTIONAL] seconds to wait before evaluating — CloudWatch-sourced metrics arrive late"
  type        = number
  default     = null
}

variable "renotify_interval" {
  description = "[OPTIONAL] minutes between re-notifications while still alerting"
  type        = number
  default     = null
}

variable "priority" {
  description = "[OPTIONAL] Datadog priority, 1 (highest) to 5"
  type        = number
  default     = null
}

variable "notifiers" {
  description = "[OPTIONAL] the default notifier handles"
  type        = list(string)
  default     = ["@slack-giano-alerts"]
}

variable "additional_notifiers" {
  description = "[OPTIONAL] extra notifier handles for this monitor"
  type        = list(string)
  default     = []
}

variable "additional_tags" {
  description = "[OPTIONAL] tags to attach. Pass the deployment's default_tags — Datadog has no provider-level equivalent"
  type        = map(any)
  default     = {}
}
