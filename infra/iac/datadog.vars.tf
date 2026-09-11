# §17.3

variable "datadog_site" {
  description = "must agree with the Agent's DD_SITE and the FireLens Host — R16"
  type        = string
  default     = "datadoghq.com"
}

variable "datadog_enabled" {
  description = "gates the provider's `validate`, the sidecars, and the monitors"
  type        = map(bool)
  default     = { dev = true, stg = true, prd = true }
}

# R24 — the Datadog API key has no rotation trigger of its own; it lives in a shared DevOps
# note with nowhere to carry a version. Bump this by hand whenever that key is rotated, or
# Secrets Manager keeps the old one and every task silently stops reporting.
variable "datadog_api_key_version" {
  description = "bump to rotate the mirrored Datadog API key — §7.4, R24"
  type        = number
  default     = 1
}

variable "datadog_monitors_enabled" {
  description = "a workspace can run the Agent without paging anyone — §17.3.5"
  type        = map(bool)
  default     = { dev = true, stg = true, prd = true }
}

variable "datadog_monitor_additional_notifiers" {
  description = "extra notifier handles beyond the default @slack-giano-alerts"
  type        = list(string)
  default     = []
}

variable "datadog_cert_expiry_threshold_days" {
  description = "certificate expiry monitor threshold — §17.3.5"
  type        = number
  default     = 30
}
