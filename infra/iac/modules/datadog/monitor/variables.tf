# §17.3.5

variable "name" {
  description = "[REQUIRED]"
  type        = string
}

variable "query" {
  description = "[REQUIRED] the Datadog monitor query"
  type        = string
}

variable "monitor_type" {
  description = "[OPTIONAL]"
  type        = string
  default     = "metric alert"
}

variable "monitor_thresholds" {
  description = "[OPTIONAL] at minimum `critical`; `warning` and `ok` are optional"
  type = object({
    critical = optional(number)
    warning  = optional(number)
    ok       = optional(number)
  })
  default = {}
}

variable "notify_no_data" {
  description = "[OPTIONAL] the point of the no-metrics monitor is the ABSENCE of data, not the value — §17.3.5"
  type        = bool
  default     = false
}

variable "no_data_timeframe" {
  description = "[OPTIONAL] minutes of silence before notify_no_data fires"
  type        = number
  default     = null
}

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
