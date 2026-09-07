<<<<<<< HEAD
# §17.3

variable "datadog_site" {
  description = "must agree with the Agent's DD_SITE and the FireLens Host — R16"
  type        = string
  default     = "datadoghq.com"
}

variable "datadog_enabled" {
  description = "gates the provider's `validate`, the sidecars, and the monitors"
=======
variable "datadog_site" {
  description = "[REQUIRED] Datadog site, matching the org's existing account. A variable and not a literal because it appears in the provider's api_url, the Agent's DD_SITE and the FireLens Host, and a mismatch between them is a silent half-outage — metrics arrive, logs do not (R16)"
  type        = string

  # §17.3.2 says datadoghq.eu; the account's own keys say otherwise. Verified
  # against the DevOps item: api/v1/validate returns 200 on datadoghq.com and
  # 403 on datadoghq.eu, which is exactly the 403 the provider reported.
  default = "datadoghq.com"
}

variable "datadog_enabled" {
  description = "[REQUIRED] whether tasks carry the Agent and FireLens sidecars, per environment. With it off the application logs to CloudWatch instead"
>>>>>>> main
  type        = map(bool)
  default     = { dev = true, stg = true, prd = true }
}

<<<<<<< HEAD
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
=======
variable "datadog_monitors_enabled" {
  description = "[REQUIRED] whether the monitors are created, per environment — so a workspace can run the Agent without paging anyone"
>>>>>>> main
  type        = map(bool)
  default     = { dev = true, stg = true, prd = true }
}

variable "datadog_monitor_additional_notifiers" {
<<<<<<< HEAD
  description = "extra notifier handles beyond the default @slack-giano-alerts"
=======
  description = "[OPTIONAL] notifier handles beyond the module's default of @slack-giano-alerts"
>>>>>>> main
  type        = list(string)
  default     = []
}

<<<<<<< HEAD
variable "datadog_cert_expiry_threshold_days" {
  description = "certificate expiry monitor threshold — §17.3.5"
  type        = number
  default     = 30
=======
variable "chain_balance_floors" {
  description = "[REQUIRED] { account => floor } for the funded-account monitor, in the unit §16.6's emitter submits (ETH). Both accounts drain with every sponsored transaction (§13.2)"
  type        = map(number)
  default = {
    executor  = 0.05
    paymaster = 0.05
  }
>>>>>>> main
}
