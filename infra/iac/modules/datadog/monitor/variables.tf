<<<<<<< HEAD
# §17.3.5

variable "name" {
  description = "[REQUIRED]"
=======
variable "name" {
  description = "[REQUIRED] monitor name, as it appears in Datadog and in the alert"
>>>>>>> main
  type        = string
}

variable "query" {
<<<<<<< HEAD
  description = "[REQUIRED] the Datadog monitor query"
  type        = string
}

variable "monitor_type" {
  description = "[OPTIONAL]"
=======
  description = "[REQUIRED] the monitor query"
  type        = string
}

variable "type" {
  description = "[OPTIONAL] monitor type"
>>>>>>> main
  type        = string
  default     = "metric alert"
}

<<<<<<< HEAD
variable "monitor_thresholds" {
  description = "[OPTIONAL] at minimum `critical`; `warning` and `ok` are optional"
  type = object({
    critical = optional(number)
    warning  = optional(number)
    ok       = optional(number)
=======
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
>>>>>>> main
  })
  default = {}
}

variable "notify_no_data" {
<<<<<<< HEAD
  description = "[OPTIONAL] the point of the no-metrics monitor is the ABSENCE of data, not the value — §17.3.5"
=======
  description = "[OPTIONAL] alert when the query stops returning data. The whole mechanism of the Agent-liveness monitor (R17)"
>>>>>>> main
  type        = bool
  default     = false
}

variable "no_data_timeframe" {
<<<<<<< HEAD
  description = "[OPTIONAL] minutes of silence before notify_no_data fires"
=======
  description = "[OPTIONAL] minutes of silence before a no-data alert"
>>>>>>> main
  type        = number
  default     = null
}

<<<<<<< HEAD
variable "message" {
  description = "[OPTIONAL] prepended to the notifier list in the monitor's message"
  type        = string
  default     = ""
}

# datadog_monitor has its own tag concept, with no default_tags from the provider — this is
# the ONE place hand-merging the default tags is correct (§4.3.1).
variable "additional_tags" {
  description = "[REQUIRED] plain { key => value } map — usually local.default_tags"
  type        = map(string)
}

variable "additional_notifiers" {
  description = "[OPTIONAL] extra @-handles beyond the built-in @slack-giano-alerts default"
  type        = list(string)
  default     = []
}
=======
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
>>>>>>> main
